use crate::utils::{deserialize_json_file, sha256, SysConfig};
use anyhow::{anyhow, bail, Context, Result};
use dstack_types::shared_filenames::{HOST_SHARED_DIR, SYS_CONFIG};
use host_api::{
    client::{new_client, DefaultClient},
    Notification,
};
use ra_tls::attestation::validate_tcb;
use sodiumbox::{generate_keypair, open_sealed_box, PUBLICKEYBYTES};
use tracing::warn;

pub(crate) struct KeyProvision {
    pub sk: [u8; 32],
    pub mr: [u8; 32],
}

pub(crate) struct HostApi {
    client: DefaultClient,
    pccs_url: Option<String>,
}

impl Default for HostApi {
    fn default() -> Self {
        Self::new("".into(), None)
    }
}

impl HostApi {
    pub fn new(base_url: String, pccs_url: Option<String>) -> Self {
        Self {
            client: new_client(base_url),
            pccs_url,
        }
    }

    pub fn load_or_default(url: Option<String>) -> Result<Self> {
        let api = match url {
            Some(url) => Self::new(url, None),
            None => {
                let local_config: SysConfig =
                    deserialize_json_file(format!("{HOST_SHARED_DIR}/{SYS_CONFIG}"))?;
                Self::new(
                    local_config.host_api_url.clone(),
                    local_config.pccs_url.clone(),
                )
            }
        };
        Ok(api)
    }

    pub async fn notify(&self, event: &str, payload: &str) -> Result<()> {
        self.client
            .notify(Notification {
                event: event.to_string(),
                payload: payload.to_string(),
            })
            .await?;
        Ok(())
    }

    pub async fn notify_q(&self, event: &str, payload: &str) {
        if let Err(err) = self.notify(event, payload).await {
            warn!("Failed to notify event {event} to host: {:?}", err);
        }
    }
    fn create_mock_quote(report_data: &[u8]) -> Vec<u8> {
        // 基于 TDX quote 格式构建更真实的模拟数据
        let mut mock_quote = Vec::new();
        
        // ECDSA Quote 头部 (4 字节版本 + 4 字节 attestation key type)
        mock_quote.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // 版本 3
        mock_quote.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // ECDSA 签名类型
        
        // QE Vendor ID (16 字节)
        mock_quote.extend_from_slice(&[0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 
                                    0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07]);
        
        // 用户数据长度 (2 字节) - 设为 0
        mock_quote.extend_from_slice(&[0x00, 0x00]);
        
        // Quote 认证数据 - 包含 report_data (64 bytes)
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&[0x00; 32]); // TD Report 头部
        auth_data.extend_from_slice(report_data);  // Report Data (64 bytes)
        auth_data.extend_from_slice(&[0x00; 128]); // 其他 TD Report 数据
        
        // 添加 auth_data 长度 (4 字节)
        let auth_data_len = auth_data.len() as u32;
        mock_quote.extend_from_slice(&auth_data_len.to_le_bytes());
        
        // 添加 auth_data
        mock_quote.extend_from_slice(&auth_data);
        
        // 添加签名部分
        let signature_size = 128u32;
        mock_quote.extend_from_slice(&signature_size.to_le_bytes());
        mock_quote.extend_from_slice(&[0xBB; 128]); // 模拟 ECDSA 签名
        
        mock_quote
    }
    pub async fn get_sealing_key(&self) -> Result<KeyProvision> {
        let (pk, sk) = generate_keypair();
        let mut report_data = [0u8; 64];
        report_data[..PUBLICKEYBYTES].copy_from_slice(pk.as_bytes());
        let quote = Self::create_mock_quote(&report_data);
        //let (_, quote) =
        //    tdx_attest::get_quote(&report_data, None).context("Failed to get quote")?;

        let provision = self
            .client
            .get_sealing_key(host_api::GetSealingKeyRequest {
                quote: quote.to_vec(),
            })
            .await
            .map_err(|err| anyhow!("Failed to get sealing key: {err:?}"))?;

        // verify the key provider quote
        let verified_report = dcap_qvl::collateral::get_collateral_and_verify(
            &provision.provider_quote,
            self.pccs_url.as_deref(),
        )
        .await
        .context("Failed to get quote collateral")?;
        validate_tcb(&verified_report)?;
        let sgx_report = verified_report
            .report
            .as_sgx()
            .context("Invalid sgx report")?;
        let key_hash = sha256(&provision.encrypted_key);
        if sgx_report.report_data[..32] != key_hash {
            bail!("Invalid key hash");
        }
        let mr = sgx_report.mr_enclave;

        // write to fs
        let sealing_key = open_sealed_box(&provision.encrypted_key, &pk, &sk)
            .ok()
            .context("Failed to open sealing key")?;
        let sk = sealing_key
            .try_into()
            .ok()
            .context("Invalid sealing key length")?;
        Ok(KeyProvision { sk, mr })
    }
}
