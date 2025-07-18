use load_config::load_config;
use rocket::figment::Figment;
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
// 定义默认配置文件的内容
pub const DEFAULT_CONFIG: &str = include_str!("../kms.toml");
// 加载配置文件并返回一个 Figment 实例
pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("kms", DEFAULT_CONFIG, config_file, false)
}

const TEMP_CA_CERT: &str = "tmp-ca.crt";
const TEMP_CA_KEY: &str = "tmp-ca.key";
const ROOT_CA_CERT: &str = "root-ca.crt";
const ROOT_CA_KEY: &str = "root-ca.key";
const RPC_CERT: &str = "rpc.crt";
const RPC_KEY: &str = "rpc.key";
const RPC_DOMAIN: &str = "rpc-domain";
const K256_KEY: &str = "root-k256.key";
const BOOTSTRAP_INFO: &str = "bootstrap-info.json";

// 定义与镜像相关的配置
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ImageConfig {
    pub verify: bool,
    pub cache_dir: PathBuf,
    pub download_url: String,
    #[serde(with = "serde_duration")]
    pub download_timeout: Duration,
}
// 定义 KMS 的主配置结构体
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KmsConfig {
    pub cert_dir: PathBuf,
    pub pccs_url: Option<String>,
    pub auth_api: AuthApi,
    pub onboard: OnboardConfig,
    pub image: ImageConfig,
    #[serde(with = "serde_human_bytes")]
    pub admin_token_hash: Vec<u8>,
}

impl KmsConfig {
    // 检查所有密钥文件是否存在
    pub fn keys_exists(&self) -> bool {
        self.tmp_ca_cert().exists()
            && self.tmp_ca_key().exists()
            && self.root_ca_cert().exists()
            && self.root_ca_key().exists()
            && self.rpc_cert().exists()
            && self.rpc_key().exists()
            && self.k256_key().exists()
    }
    // 返回各种证书和密钥文件的路径
    pub fn tmp_ca_cert(&self) -> PathBuf {
        self.cert_dir.join(TEMP_CA_CERT)
    }

    pub fn tmp_ca_key(&self) -> PathBuf {
        self.cert_dir.join(TEMP_CA_KEY)
    }

    pub fn root_ca_cert(&self) -> PathBuf {
        self.cert_dir.join(ROOT_CA_CERT)
    }

    pub fn root_ca_key(&self) -> PathBuf {
        self.cert_dir.join(ROOT_CA_KEY)
    }

    pub fn rpc_cert(&self) -> PathBuf {
        self.cert_dir.join(RPC_CERT)
    }

    pub fn rpc_key(&self) -> PathBuf {
        self.cert_dir.join(RPC_KEY)
    }

    pub fn rpc_domain(&self) -> PathBuf {
        self.cert_dir.join(RPC_DOMAIN)
    }

    pub fn k256_key(&self) -> PathBuf {
        self.cert_dir.join(K256_KEY)
    }

    pub fn bootstrap_info(&self) -> PathBuf {
        self.cert_dir.join(BOOTSTRAP_INFO)
    }
}

// 定义身份验证 API 的配置
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum AuthApi {
    #[serde(rename = "dev")]
    Dev { dev: Dev },
    #[serde(rename = "webhook")]
    Webhook { webhook: Webhook },
}

impl AuthApi {
    // 检查是否是开发模式
    pub fn is_dev(&self) -> bool {
        matches!(self, AuthApi::Dev { .. })
    }
}

// 定义 Webhook 模式的配置
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Webhook {
    pub url: String,
}

// 定义开发模式的配置
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Dev {
    pub gateway_app_id: String,
}

// 定义引导配置
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OnboardConfig {
    pub enabled: bool,
    pub quote_enabled: bool,
    pub auto_bootstrap_domain: String,
}
