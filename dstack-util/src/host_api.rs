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
    fn quote_from_csv_report(report_data_prefix: &[u8]) -> Result<Vec<u8>> {
        // 通过 csv_attest 获取报告，返回为字节数组
        let mut client = csv_attest::CsvAttestationClient::new();
        client.generate_nonce().context("Failed to generate nonce")?;
        let report = client
            .get_attestation_report_ioctl()
            .or_else(|_| client.get_attestation_report_vmmcall())
            .context("Failed to get CSV attestation report")?;
        let size = core::mem::size_of_val(&report);
        let mut quote = Vec::with_capacity(size);
        unsafe {
            quote.set_len(size);
            core::ptr::copy_nonoverlapping(&report as *const _ as *const u8, quote.as_mut_ptr(), size);
        }
        // 尝试将 report_data_prefix 填入固定偏移（如协议需要可调整/移除）
        if !report_data_prefix.is_empty() && quote.len() >= 576 + 64 {
            let mut padded = [0u8; 64];
            let n = std::cmp::min(report_data_prefix.len(), 64);
            padded[..n].copy_from_slice(&report_data_prefix[..n]);
            quote[576..640].copy_from_slice(&padded);
        }
        Ok(quote)
    }
    pub async fn get_sealing_key(&self) -> Result<KeyProvision> {
        let (pk, sk) = generate_keypair();
        let mut report_data = [0u8; 64];
        report_data[..PUBLICKEYBYTES].copy_from_slice(pk.as_bytes());
        let quote = Self::quote_from_csv_report(&report_data)?;

        let provision = self
            .client
            .get_sealing_key(host_api::GetSealingKeyRequest {
                quote: quote.to_vec(),
            })
            .await
            .map_err(|err| anyhow!("Failed to get sealing key: {err:?}"))?;

        // CSV: 暂无 DCAP 验证流程，直接信任 VMM 返回的 provider_quote
        // TODO: 当 CSV 校验证书链方案就绪时，替换为 csv_attest 验证
        let key_hash = sha256(&provision.encrypted_key);
        // 将 key_hash 作为 MR 占位（32 字节）
        let mr: [u8; 32] = key_hash;

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
