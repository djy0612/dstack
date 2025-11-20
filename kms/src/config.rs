use load_config::load_config;
use rocket::figment::Figment;
use serde::Deserialize;
use std::path::PathBuf;
pub const DEFAULT_CONFIG: &str = include_str!("../kms.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("kms", DEFAULT_CONFIG, config_file, false)
}

const TEMP_CA_CERT: &str = "tmp-ca.crt";
const TEMP_CA_KEY: &str = "tmp-ca.key";
const ROOT_CA_CERT: &str = "root-ca.crt";
const ROOT_CA_KEY: &str = "root-ca.key";
const RPC_CERT: &str = "rpc.crt";
const RPC_KEY: &str = "rpc.key";
const K256_KEY: &str = "root-k256.key";
const BOOTSTRAP_INFO: &str = "bootstrap-info.json";
const KEY_VERSION_FILE: &str = "key-version.json";

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KmsConfig {
    pub cert_dir: PathBuf,
    pub pccs_url: Option<String>,
    pub auth_api: AuthApi,
    pub onboard: OnboardConfig,
}

impl KmsConfig {
    pub fn keys_exists(&self) -> bool {
        self.tmp_ca_cert().exists()
            && self.tmp_ca_key().exists()
            && self.root_ca_cert().exists()
            && self.root_ca_key().exists()
            && self.rpc_cert().exists()
            && self.rpc_key().exists()
            && self.k256_key().exists()
    }

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

    pub fn k256_key(&self) -> PathBuf {
        self.cert_dir.join(K256_KEY)
    }

    pub fn bootstrap_info(&self) -> PathBuf {
        self.cert_dir.join(BOOTSTRAP_INFO)
    }

    pub fn key_version_file(&self) -> PathBuf {
        self.cert_dir.join(KEY_VERSION_FILE)
    }

    pub fn root_ca_cert_v(&self, version: u32) -> PathBuf {
        if version == 1 {
            self.root_ca_cert()
        } else {
            self.cert_dir.join(format!("root-ca-v{}.crt", version))
        }
    }

    pub fn root_ca_key_v(&self, version: u32) -> PathBuf {
        if version == 1 {
            self.root_ca_key()
        } else {
            self.cert_dir.join(format!("root-ca-v{}.key", version))
        }
    }

    pub fn k256_key_v(&self, version: u32) -> PathBuf {
        if version == 1 {
            self.k256_key()
        } else {
            self.cert_dir.join(format!("root-k256-v{}.key", version))
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum AuthApi {
    #[serde(rename = "dev")]
    Dev { dev: Dev },
    #[serde(rename = "webhook")]
    Webhook { webhook: Webhook },
}

impl AuthApi {
    pub fn is_dev(&self) -> bool {
        matches!(self, AuthApi::Dev { .. })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Webhook {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Dev {
    pub gateway_app_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OnboardConfig {
    pub enabled: bool,
    pub quote_enabled: bool,
    pub auto_bootstrap_domain: String,
}
