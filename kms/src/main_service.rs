use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use dstack_kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppId, AppKeyResponse, ClearImageCacheRequest, GetAppKeyRequest, GetKmsKeyRequest,
    GetMetaResponse, GetTempCaCertResponse, KmsKeyResponse, KmsKeys, PublicKeyResponse,
    RotateRootKeyRequest, RotateRootKeyResponse, SignCertRequest, SignCertResponse,
};
use dstack_types::VmConfig;
use fs_err as fs;
use k256::ecdsa::SigningKey;
use ra_rpc::{Attestation, CallContext, RpcCall};
use ra_tls::{
    attestation::VerifiedAttestation,
    cert::{CaCert, CertRequest, CertSigningRequest},
    kdf,
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};
use scale::Decode;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::{io::AsyncWriteExt, process::Command};
use tracing::{info, warn};
use upgrade_authority::BootInfo;
use safe_write::safe_write;

use crate::{
    config::KmsConfig,
    crypto::{derive_k256_key, sign_message},
};

mod upgrade_authority;

// 包装结构体,允许在多个线程之间安全地共享 KmsStateInner 的实例
#[derive(Clone)]
pub struct KmsState {
    inner: Arc<KmsStateInner>,
}

// 允许通过 KmsState 直接访问 KmsStateInner 的字段和方法
impl std::ops::Deref for KmsState {
    type Target = KmsStateInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct KmsStateInner {
    config: KmsConfig,//KMS 的配置信息
    root_ca: CaCert,// 根 CA 证书
    k256_key: SigningKey,// ECDSA 密钥
    temp_ca_cert: String,// 临时 CA 证书
    temp_ca_key: String,// 临时 CA 密钥
}

// 初始化 KmsState
impl KmsState {
    pub fn new(config: KmsConfig) -> Result<Self> {
        let root_ca = CaCert::load(config.root_ca_cert(), config.root_ca_key())
            .context("Failed to load root CA certificate")?;
        let key_bytes = fs::read(config.k256_key()).context("Failed to read ECDSA root key")?;
        let k256_key =
            SigningKey::from_slice(&key_bytes).context("Failed to load ECDSA root key")?;
        let temp_ca_key =
            fs::read_to_string(config.tmp_ca_key()).context("Faeild to read temp ca key")?;
        let temp_ca_cert =
            fs::read_to_string(config.tmp_ca_cert()).context("Faeild to read temp ca cert")?;
        Ok(Self {
            inner: Arc::new(KmsStateInner {
                config,
                root_ca,
                k256_key,
                temp_ca_cert,
                temp_ca_key,
            }),
        })
    }
}

pub struct RpcHandler {
    state: KmsState,//共享的 KMS 状态
    attestation: Option<VerifiedAttestation>,//来自客户端的远程证明信息
}

struct BootConfig {
    boot_info: BootInfo,//启动信息
    gateway_app_id: String,//网关应用 ID
    os_image_hash: Vec<u8>,//操作系统镜像的哈希值
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
struct Mrs {
    mrtd: String,//测量根信任
    rtmr0: String,//运行时测量寄存器
    rtmr1: String,
    rtmr2: String,
}

impl Mrs {
    //比较两个 Mrs 实例是否相等，如果不相等则返回错误
    fn assert_eq(&self, other: &Self) -> Result<()> {
        let Self {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
        } = self;
        if mrtd != &other.mrtd {
            bail!("MRTD does not match");
        }
        if rtmr0 != &other.rtmr0 {
            bail!("RTMR0 does not match");
        }
        if rtmr1 != &other.rtmr1 {
            bail!("RTMR1 does not match");
        }
        if rtmr2 != &other.rtmr2 {
            bail!("RTMR2 does not match");
        }
        Ok(())
    }
}

//从 BootInfo 实例创建 Mrs 实例，将测量值编码为十六进制字符串
impl From<&BootInfo> for Mrs {
    fn from(report: &BootInfo) -> Self {
        Self {
            mrtd: hex::encode(&report.mrtd),
            rtmr0: hex::encode(&report.rtmr0),
            rtmr1: hex::encode(&report.rtmr1),
            rtmr2: hex::encode(&report.rtmr2),
        }
    }
}

impl RpcHandler {
    // 确保 attestation 字段存在，如果不存在则返回错误
    fn ensure_attested(&self) -> Result<&VerifiedAttestation> {
        let Some(attestation) = &self.attestation else {
            bail!("No attestation provided");
        };
        Ok(attestation)
    }
    // 确保 KMS 的启动配置是允许的
    async fn ensure_kms_allowed(&self, vm_config: &str) -> Result<BootInfo> {
        let att = self.ensure_attested()?;
        // KMS 的验证
        self.ensure_app_attestation_allowed(att, true, false, vm_config)
            .await
            .map(|c| c.boot_info)
    }
    // 确保应用程序的启动配置是允许的
    async fn ensure_app_boot_allowed(&self, vm_config: &str) -> Result<BootConfig> {
        let att = self.ensure_attested()?;
        // 应用程序的验证
        self.ensure_app_attestation_allowed(att, false, false, vm_config)
            .await
    }
    // 返回存储镜像文件的缓存目录
    fn image_cache_dir(&self) -> PathBuf {
        self.state.config.image.cache_dir.join("images")
    }
    // 返回存储计算结果（如 MRs）的缓存目录
    fn mr_cache_dir(&self) -> PathBuf {
        self.state.config.image.cache_dir.join("computed")
    }
    // 删除指定的缓存目录或文件
    fn remove_cache(&self, parent_dir: &PathBuf, sub_dir: &str) -> Result<()> {
        if sub_dir.is_empty() {
            return Ok(());
        }
        if sub_dir == "all" {
            fs::remove_dir_all(parent_dir)?;
        } else {
            let path = parent_dir.join(sub_dir);
            if path.is_dir() {
                fs::remove_dir_all(path)?;
            } else {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
    // 验证提供的管理令牌是否有效
    fn ensure_admin(&self, token: &str) -> Result<()> {
        let token_hash = sha2::Sha256::new_with_prefix(token).finalize();
        if token_hash.as_slice() != self.state.config.admin_token_hash.as_slice() {
            bail!("Invalid token");
        }
        Ok(())
    }
    // 从缓存中读取 MRs
    fn get_cached_mrs(&self, key: &str) -> Result<Mrs> {
        let path = self.mr_cache_dir().join(key);
        if !path.exists() {
            bail!("Cached MRs not found");
        }
        let content = fs::read_to_string(path).context("Failed to read cached MRs")?;
        let cached_mrs: Mrs =
            serde_json::from_str(&content).context("Failed to parse cached MRs")?;
        Ok(cached_mrs)
    }
    // 将 MRs 缓存到文件中
    fn cache_mrs(&self, key: &str, mrs: &Mrs) -> Result<()> {
        let path = self.mr_cache_dir().join(key);
        fs::create_dir_all(path.parent().unwrap()).context("Failed to create cache directory")?;
        safe_write::safe_write(
            &path,
            serde_json::to_string(mrs).context("Failed to serialize cached MRs")?,
        )
        .context("Failed to write cached MRs")?;
        Ok(())
    }
    // 验证操作系统镜像的哈希值是否与预期一致
    async fn verify_os_image_hash(&self, vm_config: &VmConfig, report: &BootInfo) -> Result<()> {
        if !self.state.config.image.verify {
            info!("Image verification is disabled");
            return Ok(());
        }
        let hex_os_image_hash = hex::encode(&vm_config.os_image_hash);
        info!("Verifying image {hex_os_image_hash}");

        let verified_mrs: Mrs = report.into();

        let cache_key = {
            let vm_config =
                serde_json::to_vec(vm_config).context("Failed to serialize VM config")?;
            hex::encode(sha2::Sha256::new_with_prefix(&vm_config).finalize())
        };
        if let Ok(cached_mrs) = self.get_cached_mrs(&cache_key) {
            cached_mrs
                .assert_eq(&verified_mrs)
                .context("MRs do not match (cached)")?;
            return Ok(());
        }

        // Create a directory for the image if it doesn't exist
        let image_dir = self.image_cache_dir().join(&hex_os_image_hash);
        // Check if metadata.json exists, if not download the image
        let metadata_path = image_dir.join("metadata.json");
        if !metadata_path.exists() {
            info!("Image {} not found, downloading", hex_os_image_hash);
            tokio::time::timeout(
                self.state.config.image.download_timeout,
                self.download_image(&hex_os_image_hash, &image_dir),
            )
            .await
            .context("Download image timeout")?
            .with_context(|| format!("Failed to download image {hex_os_image_hash}"))?;
        }

        // Calculate expected MRs with dstack-mr command
        let vcpus = vm_config.cpu_count.to_string();
        let memory = vm_config.memory_size.to_string();

        let output = Command::new("dstack-mr")
            .arg("-cpu")
            .arg(vcpus)
            .arg("-memory")
            .arg(memory)
            .arg("-json")
            .arg("-metadata")
            .arg(&metadata_path)
            .output()
            .await
            .context("Failed to execute dstack-mr command")?;

        if !output.status.success() {
            bail!(
                "dstack-mr failed with exit code {}: {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Parse the expected MRs
        let expected_mrs: Mrs =
            serde_json::from_slice(&output.stdout).context("Failed to parse dstack-mr output")?;
        self.cache_mrs(&cache_key, &expected_mrs)
            .context("Failed to cache MRs")?;
        expected_mrs
            .assert_eq(&verified_mrs)
            .context("MRs do not match")?;
        Ok(())
    }
    // 下载并验证操作系统镜像
    async fn download_image(&self, hex_os_image_hash: &str, dst_dir: &Path) -> Result<()> {
        // Create a hex representation of the os_image_hash for URL and directory naming
        let url = self
            .state
            .config
            .image
            .download_url
            .replace("{OS_IMAGE_HASH}", hex_os_image_hash);

        // Create a temporary directory for extraction within the cache directory
        let cache_dir = self.image_cache_dir().join("tmp");
        fs::create_dir_all(&cache_dir).context("Failed to create cache directory")?;
        let auto_delete_temp_dir = tempfile::Builder::new()
            .prefix("tmp-download-")
            .tempdir_in(&cache_dir)
            .context("Failed to create temporary directory")?;
        let tmp_dir = auto_delete_temp_dir.path();
        // Download the image tarball
        info!("Downloading image from {}", url);
        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .send()
            .await
            .context("Failed to download image")?;

        if !response.status().is_success() {
            bail!(
                "Failed to download image: HTTP status {}, url: {url}",
                response.status(),
            );
        }

        // Save the tarball to a temporary file using streaming
        let tarball_path = tmp_dir.join("image.tar.gz");
        let mut file = tokio::fs::File::create(&tarball_path)
            .await
            .context("Failed to create tarball file")?;
        let mut response = response;
        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk)
                .await
                .context("Failed to write chunk to file")?;
        }

        let extracted_dir = tmp_dir.join("extracted");
        fs::create_dir_all(&extracted_dir).context("Failed to create extraction directory")?;

        // Extract the tarball
        let output = Command::new("tar")
            .arg("xzf")
            .arg(&tarball_path)
            .current_dir(&extracted_dir)
            .output()
            .await
            .context("Failed to extract tarball")?;

        if !output.status.success() {
            bail!(
                "Failed to extract tarball: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Verify checksum
        let output = Command::new("sha256sum")
            .arg("-c")
            .arg("sha256sum.txt")
            .current_dir(&extracted_dir)
            .output()
            .await
            .context("Failed to verify checksum")?;

        if !output.status.success() {
            bail!(
                "Checksum verification failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // Remove the files that are not listed in sha256sum.txt
        let sha256sum_path = extracted_dir.join("sha256sum.txt");
        let files_doc =
            fs::read_to_string(&sha256sum_path).context("Failed to read sha256sum.txt")?;
        let listed_files: Vec<&OsStr> = files_doc
            .lines()
            .flat_map(|line| line.split_whitespace().nth(1))
            .map(|s| s.as_ref())
            .collect();
        let files = fs::read_dir(&extracted_dir).context("Failed to read directory")?;
        for file in files {
            let file = file.context("Failed to read directory entry")?;
            let filename = file.file_name();
            if !listed_files.contains(&filename.as_os_str()) {
                if file.path().is_dir() {
                    fs::remove_dir_all(file.path()).context("Failed to remove directory")?;
                } else {
                    fs::remove_file(file.path()).context("Failed to remove file")?;
                }
            }
        }

        // os_image_hash should eq to sha256sum of the sha256sum.txt
        let os_image_hash = sha2::Sha256::new_with_prefix(files_doc.as_bytes()).finalize();
        if hex::encode(os_image_hash) != hex_os_image_hash {
            bail!("os_image_hash does not match sha256sum of the sha256sum.txt");
        }

        // Move the extracted files to the destination directory
        let metadata_path = extracted_dir.join("metadata.json");
        if !metadata_path.exists() {
            bail!("metadata.json not found in the extracted archive");
        }

        if dst_dir.exists() {
            fs::remove_dir_all(dst_dir).context("Failed to remove destination directory")?;
        }
        let dst_dir_parent = dst_dir.parent().context("Failed to get parent directory")?;
        fs::create_dir_all(dst_dir_parent).context("Failed to create parent directory")?;
        // Move the extracted files to the destination directory
        fs::rename(extracted_dir, dst_dir)
            .context("Failed to move extracted files to destination directory")?;
        Ok(())
    }

    // 确保应用程序的验证证明是允许的
    async fn ensure_app_attestation_allowed(
        &self,
        att: &VerifiedAttestation,
        is_kms: bool,
        use_boottime_mr: bool,
        vm_config: &str,
    ) -> Result<BootConfig> {
        // CSV: 通过 att.decode_app_info 获取度量信息（CSV 无 TD 报告）
        let app_info = att.decode_app_info(use_boottime_mr)?;
        let vm_config: VmConfig =
            serde_json::from_str(vm_config).context("Failed to decode VM config")?;
        let os_image_hash = vm_config.os_image_hash.clone();
        let boot_info = BootInfo {
            mrtd: app_info.mrtd.to_vec(),
            rtmr0: app_info.rtmr0.to_vec(),
            rtmr1: app_info.rtmr1.to_vec(),
            rtmr2: app_info.rtmr2.to_vec(),
            rtmr3: app_info.rtmr3.to_vec(),
            mr_aggregated: app_info.mr_aggregated.to_vec(),
            os_image_hash: os_image_hash.clone(),
            mr_system: app_info.mr_system.to_vec(),
            app_id: app_info.app_id,
            compose_hash: app_info.compose_hash,
            instance_id: app_info.instance_id,
            device_id: app_info.device_id,
            key_provider_info: app_info.key_provider_info,
            event_log: String::from_utf8(att.raw_event_log.clone())
                .context("Failed to serialize event log")?,
            tcb_status: att.report.status.clone(),
            advisory_ids: att.report.advisory_ids.clone(),
        };
        let response = self
            .state
            .config
            .auth_api
            .is_app_allowed(&boot_info, is_kms)
            .await?;
        if !response.is_allowed {
            bail!("Boot denied: {}", response.reason);
        }
        self.verify_os_image_hash(&vm_config, &boot_info)
            .await
            .context("Failed to verify os image hash")?;
        Ok(BootConfig {
            boot_info,
            gateway_app_id: response.gateway_app_id,
            os_image_hash,
        })
    }

    // 为应用程序派生 CA 证书
    fn derive_app_ca(&self, app_id: &[u8]) -> Result<CaCert> {
        let context_data = vec![app_id, b"app-ca"];
        //使用 KDF 派生 ECDSA 密钥对
        let app_key = kdf::derive_ecdsa_key_pair(&self.state.root_ca.key, &context_data)
            .context("Failed to derive app disk key")?;
        //构造证书请求
        let req = CertRequest::builder()
            .key(&app_key)
            .org_name("Dstack")
            .subject("Dstack App CA")
            .ca_level(0)
            .app_id(app_id)
            .special_usage("app:ca")
            .build();
        //签名证书请求
        let app_ca = self
            .state
            .root_ca
            .sign(req)
            .context("Failed to sign App CA")?;
        //返回生成的 CA 证书
        Ok(CaCert::from_parts(app_key, app_ca))
    }
}

impl KmsRpc for RpcHandler {
    // 为应用程序生成和返回密钥
    async fn get_app_key(self, request: GetAppKeyRequest) -> Result<AppKeyResponse> {
        if request.api_version > 1 {
            bail!("Unsupported API version: {}", request.api_version);
        }
        let BootConfig {
            boot_info,
            gateway_app_id,
            os_image_hash,
        } = self
            .ensure_app_boot_allowed(&request.vm_config)
            .await
            .context("App not allowed")?;
        let app_id = boot_info.app_id;
        let instance_id = boot_info.instance_id;

        let context_data = vec![&app_id[..], &instance_id[..], b"app-disk-crypt-key"];
        // 使用 KDF 派生应用程序的磁盘加密密钥和环境加密密钥
        let app_disk_key = kdf::derive_dh_secret(&self.state.root_ca.key, &context_data)
            .context("Failed to derive app disk key")?;
        let env_crypt_key = {
            let secret =
                kdf::derive_dh_secret(&self.state.root_ca.key, &[&app_id[..], b"env-encrypt-key"])
                    .context("Failed to derive env encrypt key")?;
            let secret = x25519_dalek::StaticSecret::from(secret);
            secret.to_bytes()
        };

        let (k256_key, k256_signature) = {
            let (k256_app_key, signature) = derive_k256_key(&self.state.k256_key, &app_id)
                .context("Failed to derive app ecdsa key")?;
            (k256_app_key.to_bytes().to_vec(), signature)
        };

        Ok(AppKeyResponse {
            ca_cert: self.state.root_ca.pem_cert.clone(),
            disk_crypt_key: app_disk_key.to_vec(),
            env_crypt_key: env_crypt_key.to_vec(),
            k256_key,
            k256_signature,
            tproxy_app_id: gateway_app_id.clone(),
            gateway_app_id,
            os_image_hash,
        })
    }
    // 为应用程序生成环境加密的公钥
    async fn get_app_env_encrypt_pub_key(self, request: AppId) -> Result<PublicKeyResponse> {
        let secret = kdf::derive_dh_secret(
            &self.state.root_ca.key,
            &[&request.app_id[..], "env-encrypt-key".as_bytes()],
        )
        .context("Failed to derive env encrypt key")?;
        let secret = x25519_dalek::StaticSecret::from(secret);
        let pubkey = x25519_dalek::PublicKey::from(&secret);

        let public_key = pubkey.to_bytes().to_vec();
        let signature = sign_message(
            &self.state.k256_key,
            b"dstack-env-encrypt-pubkey",
            &request.app_id,
            &public_key,
        )
        .context("Failed to sign the public key")?;

        Ok(PublicKeyResponse {
            public_key,
            signature,
        })
    }
    // 返回 KMS 的元数据
    async fn get_meta(self) -> Result<GetMetaResponse> {
        let bootstrap_info = fs::read_to_string(self.state.config.bootstrap_info())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        let info = self.state.config.auth_api.get_info().await?;
        Ok(GetMetaResponse {
            ca_cert: self.state.inner.root_ca.pem_cert.clone(),
            allow_any_upgrade: self.state.inner.config.auth_api.is_dev(),
            k256_pubkey: self
                .state
                .inner
                .k256_key
                .verifying_key()
                .to_sec1_bytes()
                .to_vec(),
            bootstrap_info,
            is_dev: self.state.config.auth_api.is_dev(),
            kms_contract_address: info.kms_contract_address,
            chain_id: info.chain_id,
            gateway_app_id: info.gateway_app_id,
            app_auth_implementation: info.app_auth_implementation,
        })
    }
    // 返回 KMS 的密钥信息
    async fn get_kms_key(self, request: GetKmsKeyRequest) -> Result<KmsKeyResponse> {
        if self.state.config.onboard.quote_enabled {
            let _info = self.ensure_kms_allowed(&request.vm_config).await?;
        }
        Ok(KmsKeyResponse {
            temp_ca_key: self.state.inner.temp_ca_key.clone(),
            keys: vec![KmsKeys {
                ca_key: self.state.inner.root_ca.key.serialize_pem(),
                k256_key: self.state.inner.k256_key.to_bytes().to_vec(),
            }],
        })
    }
    // 返回临时 CA 证书和密钥
    async fn get_temp_ca_cert(self) -> Result<GetTempCaCertResponse> {
        Ok(GetTempCaCertResponse {
            temp_ca_cert: self.state.inner.temp_ca_cert.clone(),
            temp_ca_key: self.state.inner.temp_ca_key.clone(),
            ca_cert: self.state.inner.root_ca.pem_cert.clone(),
        })
    }
    // 为证书签名请求（CSR）签名
    async fn sign_cert(self, request: SignCertRequest) -> Result<SignCertResponse> {
        if request.api_version > 1 {
            bail!("Unsupported API version: {}", request.api_version);
        }
        let csr =
            CertSigningRequest::decode(&mut &request.csr[..]).context("Failed to parse csr")?;
        csr.verify(&request.signature)
            .context("Failed to verify csr signature")?;
        let attestation = Attestation::new(csr.quote.clone(), csr.event_log.clone())
            .context("Failed to create attestation from quote and event log")?
            .verify_with_ra_pubkey(&csr.pubkey, None)
            .await
            .context("Quote verification failed")?;
        let app_info = self
            .ensure_app_attestation_allowed(&attestation, false, true, &request.vm_config)
            .await?;
        let app_ca = self.derive_app_ca(&app_info.boot_info.app_id)?;
        let cert = app_ca
            .sign_csr(&csr, Some(&app_info.boot_info.app_id), "app:custom")
            .context("Failed to sign certificate")?;
        Ok(SignCertResponse {
            certificate_chain: vec![
                cert.pem(),
                app_ca.pem_cert.clone(),
                self.state.root_ca.pem_cert.clone(),
            ],
        })
    }

    // 清除镜像缓存
    async fn clear_image_cache(self, request: ClearImageCacheRequest) -> Result<()> {
        self.ensure_admin(&request.token)?;
        self.remove_cache(&self.image_cache_dir(), &request.image_hash)
            .context("Failed to clear image cache")?;
        self.remove_cache(&self.mr_cache_dir(), &request.config_hash)
            .context("Failed to clear MR cache")?;
        Ok(())
    }

    //在 impl kmsRpc for rpcHandler这个实现类里新增
    // 轮换根密钥
    // 
    // 注意：轮换后需要重启 KMS 服务才能使用新密钥。
    // 所有使用旧密钥的 VM 需要重新初始化或迁移。
    async fn rotate_root_key(self, request: RotateRootKeyRequest) -> Result<RotateRootKeyResponse> {
        // 验证管理员权限
        self.ensure_admin(&request.token)?;

        info!("Starting root key rotation");

        // 保存旧密钥的公钥信息
        let old_ca_pubkey = self.state.root_ca.key.public_key_der();
        let old_k256_pubkey = self.state.k256_key.verifying_key().to_sec1_bytes().to_vec();

        // 备份旧密钥（如果需要）
        if request.backup_old_keys {
            let backup_dir = self.state.config.cert_dir.join("backup");
            fs::create_dir_all(&backup_dir)
                .context("Failed to create backup directory")?;
            
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            // 备份旧密钥文件
            if let Err(e) = fs::copy(
                self.state.config.root_ca_key(),
                backup_dir.join(format!("root-ca.key.backup.{}", timestamp)),
            ) {
                warn!("Failed to backup root CA key: {}", e);
            }
            if let Err(e) = fs::copy(
                self.state.config.k256_key(),
                backup_dir.join(format!("root-k256.key.backup.{}", timestamp)),
            ) {
                warn!("Failed to backup k256 key: {}", e);
            }
            info!("Old keys backed up to {:?}", backup_dir);
        }

        // 生成新的根密钥
        let new_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate new CA key")?;
        let mut rng = rand::rngs::OsRng;
        let new_k256_key = SigningKey::random(&mut rng);

        // 生成新的根CA证书
        let new_ca_cert = CertRequest::builder()
            .org_name("Dstack")
            .subject("Dstack KMS CA")
            .ca_level(1)
            .key(&new_ca_key)
            .build()
            .self_signed()
            .context("Failed to generate new CA certificate")?;

        // 保存新密钥到文件
        safe_write(
            &self.state.config.root_ca_key(),
            new_ca_key.serialize_pem(),
        )
        .context("Failed to write new root CA key")?;

        safe_write(
            &self.state.config.root_ca_cert(),
            new_ca_cert.pem(),
        )
        .context("Failed to write new root CA certificate")?;

        safe_write(
            &self.state.config.k256_key(),
            new_k256_key.to_bytes(),
        )
        .context("Failed to write new k256 key")?;

        // 获取新密钥的公钥
        let new_ca_pubkey = new_ca_key.public_key_der();
        let new_k256_pubkey = new_k256_key.verifying_key().to_sec1_bytes().to_vec();

        info!("Root keys rotated successfully");
        warn!("⚠️  IMPORTANT: After root key rotation, all existing VMs using the old keys will need to be re-initialized or migrated!");

        Ok(RotateRootKeyResponse {
            old_ca_pubkey: old_ca_pubkey.to_vec(),
            new_ca_pubkey: new_ca_pubkey.to_vec(),
            old_k256_pubkey,
            new_k256_pubkey,
        })
    }
}

impl RpcCall<KmsState> for RpcHandler {
    type PrpcService = KmsServer<Self>;

    fn construct(context: CallContext<'_, KmsState>) -> Result<Self> {
        Ok(RpcHandler {
            state: context.state.clone(),
            attestation: context.attestation,
        })
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <KmsServer<RpcHandler>>::supported_methods()
}
