use anyhow::{Context, Result};
use dstack_guest_agent_rpc::{
    dstack_guest_client::DstackGuestClient, GetQuoteResponse, RawQuoteArgs,
};
use dstack_kms_rpc::{
    kms_client::KmsClient,
    onboard_server::{OnboardRpc, OnboardServer},
    BootstrapRequest, BootstrapResponse, GetKmsKeyRequest, OnboardRequest, OnboardResponse,
};
use fs_err as fs;
use http_client::prpc::PrpcClient;
use k256::ecdsa::SigningKey;
use ra_rpc::{client::RaClient, CallContext, RpcCall};
use ra_tls::{
    attestation::QuoteContentType,
    cert::{CaCert, CertRequest},
    rcgen::{Certificate, KeyPair, PKCS_ECDSA_P256_SHA256},
};
use safe_write::safe_write;

use crate::config::KmsConfig;

// 表示引导状态，包含 KMS 的配置信息
#[derive(Clone)]
pub struct OnboardState {
    config: KmsConfig,
}

impl OnboardState {
    pub fn new(config: KmsConfig) -> Self {
        Self { config }
    }
}

// 处理引导相关的 RPC 请求
pub struct OnboardHandler {
    state: OnboardState,
}

impl RpcCall<OnboardState> for OnboardHandler {
    type PrpcService = OnboardServer<Self>;

    fn construct(context: CallContext<'_, OnboardState>) -> Result<Self> {
        Ok(OnboardHandler {
            state: context.state.clone(),
        })
    }
}

impl OnboardRpc for OnboardHandler {
    // 处理引导请求，生成密钥并返回响应
    async fn bootstrap(self, request: BootstrapRequest) -> Result<BootstrapResponse> {
        let quote_enabled = self.state.config.onboard.quote_enabled;
        let keys = Keys::generate(&request.domain, quote_enabled)
            .await
            .context("Failed to generate keys")?;

        let k256_pubkey = keys.k256_key.verifying_key().to_sec1_bytes().to_vec();
        let ca_pubkey = keys.ca_key.public_key_der();
        let quote;
        let eventlog;
        if quote_enabled {
            (quote, eventlog) = quote_keys(&ca_pubkey, &k256_pubkey).await?;
        } else {
            quote = vec![];
            eventlog = vec![];
        };

        let cfg = &self.state.config;
        let response = BootstrapResponse {
            ca_pubkey,
            k256_pubkey,
            quote,
            eventlog,
        };
        // Store the bootstrap info
        safe_write(cfg.bootstrap_info(), serde_json::to_vec(&response)?)?;
        keys.store(cfg)?;
        Ok(response)
    }
    // 处理引导请求，与远程 KMS 服务交互并存储密钥
    async fn onboard(self, request: OnboardRequest) -> Result<OnboardResponse> {
        let keys = Keys::onboard(
            &request.source_url,
            &request.domain,
            self.state.config.onboard.quote_enabled,
            self.state.config.pccs_url.clone(),
        )
        .await
        .context("Failed to onboard")?;
        keys.store(&self.state.config)
            .context("Failed to store keys")?;
        Ok(OnboardResponse {})
    }
    // 处理结束请求
    async fn finish(self) -> anyhow::Result<()> {
        std::process::exit(0);
    }
}

struct Keys {
    k256_key: SigningKey,
    tmp_ca_key: KeyPair,
    tmp_ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert: Certificate,
    rpc_key: KeyPair,
    rpc_cert: Certificate,
    rpc_domain: String,
}

impl Keys {
    // 生成密钥和证书
    async fn generate(domain: &str, quote_enabled: bool) -> Result<Self> {
        let tmp_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let k256_key = SigningKey::random(&mut rand::rngs::OsRng);
        Self::from_keys(tmp_ca_key, ca_key, rpc_key, k256_key, domain, quote_enabled).await
    }
    // 从给定的密钥生成证书
    async fn from_keys(
        tmp_ca_key: KeyPair,
        ca_key: KeyPair,
        rpc_key: KeyPair,
        k256_key: SigningKey,
        domain: &str,
        quote_enabled: bool,
    ) -> Result<Self> {
        let tmp_ca_cert = CertRequest::builder()
            .org_name("Dstack")
            .subject("Dstack Client Temp CA")
            .ca_level(0)
            .key(&tmp_ca_key)
            .build()
            .self_signed()?;

        // Create self-signed KMS cert
        let ca_cert = CertRequest::builder()
            .org_name("Dstack")
            .subject("Dstack KMS CA")
            .ca_level(1)
            .key(&ca_key)
            .build()
            .self_signed()?;

        let mut quote = None;
        let mut event_log = None;

        if quote_enabled {
            let pubkey = rpc_key.public_key_der();
            let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
            let resposne = app_quote(report_data.to_vec())
                .await
                .context("Failed to get quote")?;
            quote = Some(resposne.quote);
            event_log = Some(resposne.event_log.into_bytes());
        };

        // Sign WWW server cert with KMS cert
        let rpc_cert = CertRequest::builder()
            .subject(domain)
            .alt_names(&[domain.to_string()])
            .special_usage("kms:rpc")
            .maybe_quote(quote.as_deref())
            .maybe_event_log(event_log.as_deref())
            .key(&rpc_key)
            .build()
            .signed_by(&ca_cert, &ca_key)?;
        Ok(Keys {
            k256_key,
            tmp_ca_key,
            tmp_ca_cert,
            ca_key,
            ca_cert,
            rpc_key,
            rpc_cert,
            rpc_domain: domain.to_string(),
        })
    }
    // 与远程 KMS 服务交互，获取密钥并生成本地密钥和证书
    async fn onboard(
        other_kms_url: &str,
        domain: &str,
        quote_enabled: bool,
        pccs_url: Option<String>,
    ) -> Result<Self> {
        let kms_client = RaClient::new(other_kms_url.into(), true)?;
        let mut kms_client = KmsClient::new(kms_client);

        if quote_enabled {
            let tmp_ca = kms_client.get_temp_ca_cert().await?;
            let (ra_cert, ra_key) = gen_ra_cert(tmp_ca.temp_ca_cert, tmp_ca.temp_ca_key).await?;
            let ra_client = RaClient::new_mtls(other_kms_url.into(), ra_cert, ra_key, pccs_url)
                .context("Failed to create client")?;
            kms_client = KmsClient::new(ra_client);
        }

        let info = dstack_client().info().await.context("Failed to get info")?;
        let keys_res = kms_client
            .get_kms_key(GetKmsKeyRequest {
                vm_config: info.vm_config,
            })
            .await?;
        if keys_res.keys.len() != 1 {
            return Err(anyhow::anyhow!("Invalid keys"));
        }
        let keys = keys_res.keys[0].clone();
        let tmp_ca_key_pem = keys_res.temp_ca_key;
        let root_ca_key_pem = keys.ca_key;
        let root_k256_key = keys.k256_key;

        let rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ca_key = KeyPair::from_pem(&root_ca_key_pem).context("Failed to parse CA key")?;
        let tmp_ca_key =
            KeyPair::from_pem(&tmp_ca_key_pem).context("Failed to parse tmp CA key")?;
        let ecdsa_key =
            SigningKey::from_slice(&root_k256_key).context("Failed to parse ECDSA key")?;
        Self::from_keys(
            tmp_ca_key,
            ca_key,
            rpc_key,
            ecdsa_key,
            domain,
            quote_enabled,
        )
        .await
    }
    // 将生成的密钥和证书存储到配置文件中
    fn store(&self, cfg: &KmsConfig) -> Result<()> {
        self.store_keys(cfg)?;
        self.store_certs(cfg)?;
        safe_write(cfg.rpc_domain(), self.rpc_domain.as_bytes())?;
        Ok(())
    }
    // 分别存储密钥和证书到指定的文件路径
    fn store_keys(&self, cfg: &KmsConfig) -> Result<()> {
        safe_write(cfg.tmp_ca_key(), self.tmp_ca_key.serialize_pem())?;
        safe_write(cfg.root_ca_key(), self.ca_key.serialize_pem())?;
        safe_write(cfg.rpc_key(), self.rpc_key.serialize_pem())?;
        safe_write(cfg.k256_key(), self.k256_key.to_bytes())?;
        Ok(())
    }

    fn store_certs(&self, cfg: &KmsConfig) -> Result<()> {
        safe_write(cfg.tmp_ca_cert(), self.tmp_ca_cert.pem())?;
        safe_write(cfg.root_ca_cert(), self.ca_cert.pem())?;
        safe_write(cfg.rpc_cert(), self.rpc_cert.pem())?;
        Ok(())
    }
}
// 更新现有的密钥和证书
pub(crate) async fn update_certs(cfg: &KmsConfig) -> Result<()> {
    // Read existing keys
    let tmp_ca_key = KeyPair::from_pem(&fs::read_to_string(cfg.tmp_ca_key())?)?;
    let ca_key = KeyPair::from_pem(&fs::read_to_string(cfg.root_ca_key())?)?;
    let rpc_key = KeyPair::from_pem(&fs::read_to_string(cfg.rpc_key())?)?;

    // Read k256 key
    let k256_key_bytes = fs::read(cfg.k256_key())?;
    let k256_key = SigningKey::from_slice(&k256_key_bytes)?;

    let domain = if cfg.onboard.auto_bootstrap_domain.is_empty() {
        fs::read_to_string(cfg.rpc_domain())?
    } else {
        cfg.onboard.auto_bootstrap_domain.clone()
    };
    let domain = domain.trim();

    // Regenerate certificates using existing keys
    let keys = Keys::from_keys(
        tmp_ca_key,
        ca_key,
        rpc_key,
        k256_key,
        domain,
        cfg.onboard.quote_enabled,
    )
    .await
    .context("Failed to regenerate certificates")?;

    // Write the new certificates to files
    keys.store_certs(cfg)?;

    Ok(())
}
// 生成引导密钥并存储
pub(crate) async fn bootstrap_keys(cfg: &KmsConfig) -> Result<()> {
    let keys = Keys::generate(
        &cfg.onboard.auto_bootstrap_domain,
        cfg.onboard.quote_enabled,
    )
    .await
    .context("Failed to generate keys")?;
    keys.store(cfg)?;
    Ok(())
}
// 创建 DstackGuestClient 实例
fn dstack_client() -> DstackGuestClient<PrpcClient> {
    let address = dstack_types::dstack_agent_address();
    let http_client = PrpcClient::new(address);
    DstackGuestClient::new(http_client)
}
// 获取报价
async fn app_quote(report_data: Vec<u8>) -> Result<GetQuoteResponse> {
    let quote = dstack_client()
        .get_quote(RawQuoteArgs { report_data })
        .await?;
    Ok(quote)
}
// 生成报价和事件日志
async fn quote_keys(p256_pubkey: &[u8], k256_pubkey: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let p256_hex = hex::encode(p256_pubkey);
    let k256_hex = hex::encode(k256_pubkey);
    let content_to_quote = format!("dstack-kms-genereted-keys-v1:{p256_hex};{k256_hex};");
    let hash = keccak256(content_to_quote.as_bytes());
    let report_data = pad64(hash);
    let res = app_quote(report_data).await?;
    Ok((res.quote, res.event_log.into()))
}
// 计算 Keccak-256 哈希值
fn keccak256(msg: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(msg);
    hasher.finalize().into()
}
// 将哈希值填充到 64 字节
fn pad64(hash: [u8; 32]) -> Vec<u8> {
    let mut padded = Vec::with_capacity(64);
    padded.extend_from_slice(&hash);
    padded.resize(64, 0);
    padded
}
// 生成 RA 证书
async fn gen_ra_cert(ca_cert_pem: String, ca_key_pem: String) -> Result<(String, String)> {
    use ra_tls::cert::CertRequest;
    use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let ca = CaCert::new(ca_cert_pem, ca_key_pem)?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let quote_res = app_quote(report_data.to_vec())
        .await
        .context("Failed to get quote")?;
    let quote = quote_res.quote;
    let event_log: Vec<u8> = quote_res.event_log.into();
    let req = CertRequest::builder()
        .subject("RA-TLS TEMP Cert")
        .quote(&quote)
        .event_log(&event_log)
        .key(&key)
        .build();
    let cert = ca.sign(req).context("Failed to sign certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}
