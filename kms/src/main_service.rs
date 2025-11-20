use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use dstack_kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppId, AppKeyResponse, DeriveK256KeyRequest, DeriveK256KeyResponse, GetAppKeyRequest,
    GetMetaResponse, GetTempCaCertResponse, KeyVersionResponse, KmsKeyResponse, KmsKeys,
    PublicKeyResponse, RotateRootKeyRequest, RotateRootKeyResponse, SignCertRequest,
    SignCertResponse,
};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use ra_rpc::{Attestation, CallContext, RpcCall};
use ra_tls::{
    attestation::VerifiedAttestation,
    cert::{CaCert, CertRequest, CertSigningRequest},
    kdf,
};
use scale::Decode;
use sha2::{Digest, Sha256};
use upgrade_authority::BootInfo;

use crate::key_version::KeyVersionInfo;
use crate::{
    config::KmsConfig,
    crypto::{derive_k256_key, sign_message},
};

mod upgrade_authority;

#[derive(Clone)]
pub struct KmsState {
    inner: Arc<KmsStateInner>,
}

impl std::ops::Deref for KmsState {
    type Target = KmsStateInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct KmsStateInner {
    config: KmsConfig,
    root_ca: CaCert,
    k256_key: SigningKey,
    temp_ca_cert: String,
    temp_ca_key: String,
    key_versions: std::sync::RwLock<KeyVersionInfo>,
    // Cache for loaded keys by version - store paths instead of keys to avoid Clone issues
    keys_cache: std::sync::RwLock<HashMap<u32, ()>>,
}

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

        let key_versions = KeyVersionInfo::load(&config.key_version_file())
            .context("Failed to load key version info")?;

        // Mark version 1 as cached
        let mut keys_cache = HashMap::new();
        keys_cache.insert(1, ());

        Ok(Self {
            inner: Arc::new(KmsStateInner {
                config,
                root_ca,
                k256_key,
                temp_ca_cert,
                temp_ca_key,
                key_versions: std::sync::RwLock::new(key_versions),
                keys_cache: std::sync::RwLock::new(keys_cache),
            }),
        })
    }

    pub fn get_keys_for_version(&self, version: u32) -> Result<(CaCert, SigningKey)> {
        // For version 1, use cached keys from inner state
        if version == 1 {
            // Create new CaCert from existing one (load from disk to avoid Clone)
            let root_ca = CaCert::load(self.config.root_ca_cert(), self.config.root_ca_key())
                .context("Failed to load CA certificate for version 1")?;
            let key_bytes = fs::read(self.config.k256_key())
                .context("Failed to read ECDSA root key for version 1")?;
            let k256_key = SigningKey::from_slice(&key_bytes)
                .context("Failed to load ECDSA root key for version 1")?;
            return Ok((root_ca, k256_key));
        }

        // Load keys for this version from disk
        let root_ca = CaCert::load(
            self.config.root_ca_cert_v(version),
            self.config.root_ca_key_v(version),
        )
        .context(format!(
            "Failed to load CA certificate for version {}",
            version
        ))?;

        let key_bytes = fs::read(self.config.k256_key_v(version)).context(format!(
            "Failed to read ECDSA root key for version {}",
            version
        ))?;
        let k256_key = SigningKey::from_slice(&key_bytes).context(format!(
            "Failed to load ECDSA root key for version {}",
            version
        ))?;

        Ok((root_ca, k256_key))
    }

    pub fn get_active_keys(&self) -> Result<(CaCert, SigningKey)> {
        let key_versions = self.key_versions.read().unwrap();
        let active_version = key_versions.active_version;
        drop(key_versions);
        self.get_keys_for_version(active_version)
    }

    pub fn get_current_keys(&self) -> Result<(CaCert, SigningKey)> {
        let key_versions = self.key_versions.read().unwrap();
        let current_version = key_versions.current_version;
        drop(key_versions);
        self.get_keys_for_version(current_version)
    }
}

pub struct RpcHandler {
    state: KmsState,
    attestation: Option<VerifiedAttestation>,
}

struct BootConfig {
    boot_info: BootInfo,
    gateway_app_id: String,
}

impl RpcHandler {
    fn ensure_attested(&self) -> Result<&VerifiedAttestation> {
        let Some(attestation) = &self.attestation else {
            bail!("No attestation provided");
        };
        Ok(attestation)
    }

    async fn ensure_kms_allowed(&self) -> Result<BootInfo> {
        let att = self.ensure_attested()?;
        self.ensure_app_attestation_allowed(att, true, false)
            .await
            .map(|c| c.boot_info)
    }

    async fn ensure_app_boot_allowed(&self) -> Result<BootConfig> {
        let att = self.ensure_attested()?;
        self.ensure_app_attestation_allowed(att, false, false).await
    }

    async fn ensure_app_attestation_allowed(
        &self,
        att: &VerifiedAttestation,
        is_kms: bool,
        use_boottime_mr: bool,
    ) -> Result<BootConfig> {
        let app_info = att.decode_app_info(use_boottime_mr)?;
        let mr_key_provider = if app_info.key_provider_info.is_empty() {
            vec![0u8; 32]
        } else {
            let mut hasher = Sha256::new();
            hasher.update(&app_info.key_provider_info);
            hasher.finalize().to_vec()
        };
        let boot_info = BootInfo {
            mrtd: app_info.mrtd.to_vec(),
            rtmr0: app_info.rtmr0.to_vec(),
            rtmr1: app_info.rtmr1.to_vec(),
            rtmr2: app_info.rtmr2.to_vec(),
            rtmr3: app_info.rtmr3.to_vec(),
            mr_aggregated: app_info.mr_aggregated.to_vec(),
            mr_image: app_info.os_image_hash.clone(),
            mr_system: app_info.mr_system.to_vec(),
            mr_key_provider,
            app_id: app_info.app_id.clone(),
            compose_hash: app_info.compose_hash.clone(),
            instance_id: app_info.instance_id.clone(),
            device_id: app_info.device_id.clone(),
            key_provider_info: app_info.key_provider_info.clone(),
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
        Ok(BootConfig {
            boot_info,
            gateway_app_id: response.gateway_app_id,
        })
    }

    fn derive_app_ca(&self, app_id: &[u8], version: Option<u32>) -> Result<CaCert> {
        let (root_ca, _) = if let Some(v) = version {
            self.state.get_keys_for_version(v)?
        } else {
            self.state.get_active_keys()?
        };

        let context_data = vec![app_id, b"app-ca"];
        let app_key = kdf::derive_ecdsa_key_pair(&root_ca.key, &context_data)
            .context("Failed to derive app disk key")?;
        let req = CertRequest::builder()
            .key(&app_key)
            .org_name("Dstack")
            .subject("Dstack App CA")
            .ca_level(0)
            .app_id(app_id)
            .special_usage("app:ca")
            .build();
        let app_ca = root_ca.sign(req).context("Failed to sign App CA")?;
        Ok(CaCert::from_parts(app_key, app_ca))
    }
}

impl KmsRpc for RpcHandler {
    async fn get_app_key(self, request: GetAppKeyRequest) -> Result<AppKeyResponse> {
        let BootConfig {
            boot_info,
            gateway_app_id,
        } = self
            .ensure_app_boot_allowed()
            .await
            .context("App not allowed")?;
        let app_id = boot_info.app_id;
        let instance_id = boot_info.instance_id;

        // Determine which key version to use
        let key_version = request.key_version;
        let (root_ca, k256_key) = if key_version > 0 {
            // Check if version is active
            let key_versions = self.state.key_versions.read().unwrap();
            if !key_versions.is_version_active(key_version) {
                anyhow::bail!("Key version {} is not active", key_version);
            }
            if key_versions.is_version_deprecated(key_version) {
                anyhow::bail!("Key version {} is deprecated", key_version);
            }
            drop(key_versions);
            self.state.get_keys_for_version(key_version)?
        } else {
            self.state.get_active_keys()?
        };

        let context_data = vec![&app_id[..], &instance_id[..], b"app-disk-crypt-key"];
        let app_disk_key = kdf::derive_dh_secret(&root_ca.key, &context_data)
            .context("Failed to derive app disk key")?;
        let env_crypt_key = {
            let secret = kdf::derive_dh_secret(&root_ca.key, &[&app_id[..], b"env-encrypt-key"])
                .context("Failed to derive env encrypt key")?;
            let secret = x25519_dalek::StaticSecret::from(secret);
            secret.to_bytes()
        };

        let (k256_app_key_bytes, k256_signature) = {
            let (k256_app_key, signature) =
                derive_k256_key(&k256_key, &app_id).context("Failed to derive app ecdsa key")?;
            (k256_app_key.to_bytes().to_vec(), signature)
        };

        Ok(AppKeyResponse {
            ca_cert: root_ca.pem_cert.clone(),
            disk_crypt_key: app_disk_key.to_vec(),
            env_crypt_key: env_crypt_key.to_vec(),
            k256_key: k256_app_key_bytes,
            k256_signature,
            gateway_app_id,
        })
    }

    async fn get_app_env_encrypt_pub_key(self, request: AppId) -> Result<PublicKeyResponse> {
        let (root_ca, k256_key) = self.state.get_active_keys()?;
        let secret = kdf::derive_dh_secret(
            &root_ca.key,
            &[&request.app_id[..], "env-encrypt-key".as_bytes()],
        )
        .context("Failed to derive env encrypt key")?;
        let secret = x25519_dalek::StaticSecret::from(secret);
        let pubkey = x25519_dalek::PublicKey::from(&secret);

        let public_key = pubkey.to_bytes().to_vec();
        let signature = sign_message(
            &k256_key,
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

    async fn get_meta(self) -> Result<GetMetaResponse> {
        let (root_ca, k256_key) = self.state.get_active_keys()?;
        let bootstrap_info = fs::read_to_string(self.state.config.bootstrap_info())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        Ok(GetMetaResponse {
            ca_cert: root_ca.pem_cert.clone(),
            allow_any_upgrade: self.state.inner.config.auth_api.is_dev(),
            k256_pubkey: k256_key.verifying_key().to_sec1_bytes().to_vec(),
            bootstrap_info,
        })
    }

    async fn get_kms_key(self) -> Result<KmsKeyResponse> {
        if self.state.config.onboard.quote_enabled {
            let _info = self.ensure_kms_allowed().await?;
        }
        let (root_ca, k256_key) = self.state.get_active_keys()?;
        Ok(KmsKeyResponse {
            temp_ca_key: self.state.inner.temp_ca_key.clone(),
            keys: vec![KmsKeys {
                ca_key: root_ca.key.serialize_pem(),
                k256_key: k256_key.to_bytes().to_vec(),
            }],
        })
    }

    async fn get_temp_ca_cert(self) -> Result<GetTempCaCertResponse> {
        let (root_ca, _) = self.state.get_active_keys()?;
        Ok(GetTempCaCertResponse {
            temp_ca_cert: self.state.inner.temp_ca_cert.clone(),
            temp_ca_key: self.state.inner.temp_ca_key.clone(),
            ca_cert: root_ca.pem_cert.clone(),
        })
    }

    async fn sign_cert(self, request: SignCertRequest) -> Result<SignCertResponse> {
        let csr =
            CertSigningRequest::decode(&mut &request.csr[..]).context("Failed to parse csr")?;
        csr.verify(&request.signature)
            .context("Failed to verify csr signature")?;
        let attestation = Attestation::new(csr.quote.clone(), csr.event_log.clone())
            .context("Failed to create attestation from quote and event log")?
            .verify_with_ra_pubkey(&csr.pubkey, self.state.config.pccs_url.as_deref())
            .await
            .context("Quote verification failed")?;
        let app_info = self
            .ensure_app_attestation_allowed(&attestation, false, true)
            .await?;
        let app_ca = self.derive_app_ca(&app_info.boot_info.app_id, None)?;
        let (root_ca, _) = self.state.get_active_keys()?;
        let cert = app_ca
            .sign_csr(&csr, Some(&app_info.boot_info.app_id), "app:custom")
            .context("Failed to sign certificate")?;
        Ok(SignCertResponse {
            certificate_chain: vec![
                cert.pem(),
                app_ca.pem_cert.clone(),
                root_ca.pem_cert.clone(),
            ],
        })
    }

    async fn rotate_root_key(self, request: RotateRootKeyRequest) -> Result<RotateRootKeyResponse> {
        // Ensure KMS is allowed (only if quote verification is enabled)
        if self.state.config.onboard.quote_enabled {
            let _info = self.ensure_kms_allowed().await?;
        }

        // Determine new version and start rotation (release lock before await)
        let new_version = {
            let mut key_versions = self.state.key_versions.write().unwrap();
            let new_version = if request.target_version > 0 {
                if request.target_version <= key_versions.current_version {
                    anyhow::bail!("Target version must be greater than current version");
                }
                request.target_version
            } else {
                key_versions.current_version + 1
            };
            // Start rotation
            key_versions.start_rotation(new_version, 30)?; // 30 days grace period
            new_version
        };

        // Generate new keys
        use ra_tls::cert::CertRequest;
        use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

        let new_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let new_k256_key = SigningKey::random(&mut rand::rngs::OsRng);

        // Create new CA certificate
        let new_ca_cert = CertRequest::builder()
            .org_name("Dstack")
            .subject("Dstack KMS CA")
            .ca_level(1)
            .key(&new_ca_key)
            .build()
            .self_signed()?;

        // Get quote if enabled
        let (quote, eventlog) = if self.state.config.onboard.quote_enabled {
            use dstack_guest_agent_rpc::{dstack_guest_client::DstackGuestClient, RawQuoteArgs};
            use dstack_types::dstack_agent_address;
            use hex;
            use http_client::prpc::PrpcClient;
            use sha3::{Digest, Keccak256};

            let ca_pubkey = new_ca_key.public_key_der();
            let k256_pubkey = new_k256_key.verifying_key().to_sec1_bytes();

            let p256_hex = hex::encode(ca_pubkey);
            let k256_hex = hex::encode(k256_pubkey);
            let content_to_quote = format!("dstack-kms-genereted-keys-v1:{p256_hex};{k256_hex};");
            let hash = Keccak256::digest(content_to_quote.as_bytes());
            let mut report_data = hash.to_vec();
            report_data.resize(64, 0);

            let address = dstack_agent_address();
            let http_client = PrpcClient::new(address);
            let client = DstackGuestClient::new(http_client);
            let quote_res = client.get_quote(RawQuoteArgs { report_data }).await?;
            (quote_res.quote, quote_res.event_log.into_bytes())
        } else {
            (vec![], vec![])
        };

        // Save new keys
        use safe_write::safe_write;
        safe_write(
            self.state.config.root_ca_cert_v(new_version),
            new_ca_cert.pem(),
        )?;
        safe_write(
            self.state.config.root_ca_key_v(new_version),
            new_ca_key.serialize_pem(),
        )?;
        safe_write(
            self.state.config.k256_key_v(new_version),
            new_k256_key.to_bytes(),
        )?;

        // Update key version info and complete rotation
        {
            let mut key_versions = self.state.key_versions.write().unwrap();
            // Complete the rotation: set active_version to current_version and reset flags
            key_versions.complete_rotation();
            key_versions.save(&self.state.config.key_version_file())?;
        }

        Ok(RotateRootKeyResponse {
            new_version,
            ca_pubkey: new_ca_key.public_key_der(),
            k256_pubkey: new_k256_key.verifying_key().to_sec1_bytes().to_vec(),
            quote,
            eventlog,
        })
    }

    async fn get_key_version(self) -> Result<KeyVersionResponse> {
        let key_versions = self.state.key_versions.read().unwrap();
        Ok(KeyVersionResponse {
            current_version: key_versions.current_version,
            active_version: key_versions.active_version,
            rotation_in_progress: key_versions.rotation_in_progress,
            rotation_deadline: key_versions.rotation_deadline.unwrap_or(0),
        })
    }

    async fn derive_k256_key(self, request: DeriveK256KeyRequest) -> Result<DeriveK256KeyResponse> {
        // In dev mode, allow skipping attestation and use default app_id
        let app_id = if self.state.config.auth_api.is_dev() {
            // Try to get app_id from attestation if available
            if let Ok(BootConfig { boot_info, .. }) = self.ensure_app_boot_allowed().await {
                boot_info.app_id
            } else {
                // Dev mode: use path hash as default app_id
                use sha3::{Digest, Keccak256};
                let hash = Keccak256::digest(request.path.as_bytes());
                hash[..16].to_vec() // Use first 16 bytes as app_id
            }
        } else {
            // Production mode: must pass attestation
            let BootConfig { boot_info, .. } = self
                .ensure_app_boot_allowed()
                .await
                .context("App not allowed")?;
            boot_info.app_id
        };

        // Get app-level k256_key (from GetAppKey)
        // We need to derive it from root key using the same logic as GetAppKey
        let key_version = request.key_version;
        let (_, root_k256_key) = if key_version > 0 {
            let key_versions = self.state.key_versions.read().unwrap();
            if !key_versions.is_version_active(key_version) {
                anyhow::bail!("Key version {} is not active", key_version);
            }
            if key_versions.is_version_deprecated(key_version) {
                anyhow::bail!("Key version {} is deprecated", key_version);
            }
            drop(key_versions);
            self.state.get_keys_for_version(key_version)?
        } else {
            self.state.get_active_keys()?
        };

        // Derive app-level k256_key (same as in GetAppKey)
        let (app_k256_key, app_k256_signature) =
            derive_k256_key(&root_k256_key, &app_id).context("Failed to derive app k256 key")?;

        // Derive the requested key from app-level key using path and purpose
        use hex;
        use ra_tls::kdf::derive_ecdsa_key;
        use sha3::{Digest, Keccak256};

        // Derive key using path
        let derived_key_bytes =
            derive_ecdsa_key(&app_k256_key.to_bytes(), &[request.path.as_bytes()], 32)
                .context("Failed to derive k256 key from app key")?;

        let derived_k256_key = SigningKey::from_slice(&derived_key_bytes)
            .context("Failed to parse derived k256 key")?;
        let derived_k256_pubkey = derived_k256_key.verifying_key();

        // Sign the derived key with app key (same as guest-agent does)
        let msg_to_sign = format!(
            "{}:{}",
            request.purpose,
            hex::encode(derived_k256_pubkey.to_sec1_bytes())
        );
        let digest = Keccak256::new_with_prefix(msg_to_sign);
        let (signature, recid) = app_k256_key.sign_digest_recoverable(digest)?;
        let mut derived_key_signature = signature.to_vec();
        derived_key_signature.push(recid.to_byte());

        // Build signature chain: [derived_key_signature, app_key_signature]
        Ok(DeriveK256KeyResponse {
            k256_key: derived_k256_key.to_bytes().to_vec(),
            k256_signature_chain: vec![derived_key_signature, app_k256_signature],
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
