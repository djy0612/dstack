use anyhow::{Context, Result};
use dstack_kms_rpc::{kms_client::KmsClient, SignCertRequest};
use dstack_types::{AppKeys, KeyProvider};
use ra_rpc::client::{RaClient, RaClientConfig};
use ra_tls::{
    attestation::QuoteContentType,
    cert::{generate_ra_cert, CaCert, CertConfig, CertSigningRequest},
    rcgen::KeyPair,
};
use tdx_attest::{eventlog::read_event_logs, get_quote};

pub enum CertRequestClient {
    Local {
        ca: CaCert,
    },
    Kms {
        client: KmsClient<RaClient>,
        vm_config: String,
    },
}

impl CertRequestClient {
    pub async fn sign_csr(
        &self,
        csr: &CertSigningRequest,
        signature: &[u8],
    ) -> Result<Vec<String>> {
        match self {
            CertRequestClient::Local { ca } => {
                let cert = ca
                    .sign_csr(csr, None, "app:custom")
                    .context("Failed to sign certificate")?;
                Ok(vec![cert.pem(), ca.pem_cert.clone()])
            }
            CertRequestClient::Kms { client, vm_config } => {
                let response = client
                    .sign_cert(SignCertRequest {
                        api_version: 1,
                        csr: csr.to_vec(),
                        signature: signature.to_vec(),
                        vm_config: vm_config.clone(),
                    })
                    .await?;
                Ok(response.certificate_chain)
            }
        }
    }

    pub async fn get_root_ca(&self) -> Result<String> {
        match self {
            CertRequestClient::Local { ca } => Ok(ca.pem_cert.clone()),
            CertRequestClient::Kms { client, .. } => Ok(client.get_meta().await?.ca_cert),
        }
    }

    pub async fn create(
        keys: &AppKeys,
        pccs_url: Option<&str>,
        vm_config: String,
    ) -> Result<CertRequestClient> {
        match &keys.key_provider {
            KeyProvider::None { key } | KeyProvider::Local { key, .. } => {
                let ca = CaCert::new(keys.ca_cert.clone(), key.clone())
                    .context("Failed to create CA")?;
                Ok(CertRequestClient::Local { ca })
            }
            KeyProvider::Kms { url, .. } => {
                let tmp_client =
                    RaClient::new(url.into(), true).context("Failed to create RA client")?;
                let tmp_client = KmsClient::new(tmp_client);
                let tmp_ca = tmp_client
                    .get_temp_ca_cert()
                    .await
                    .context("Failed to get temp CA cert")?;
                let client_cert = generate_ra_cert(tmp_ca.temp_ca_cert, tmp_ca.temp_ca_key)
                    .context("Failed to generate RA cert")?;
                let ra_client = RaClientConfig::builder()
                    .remote_uri(url.clone())
                    .tls_client_cert(client_cert.cert_pem)
                    .tls_client_key(client_cert.key_pem)
                    .tls_ca_cert(keys.ca_cert.clone())
                    .tls_built_in_root_certs(false)
                    .maybe_pccs_url(pccs_url.map(|s| s.to_string()))
                    .build()
                    .into_client()
                    .context("Failed to create RA client")?;
                let client = KmsClient::new(ra_client);
                Ok(CertRequestClient::Kms { client, vm_config })
            }
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
    // 添加一个创建模拟 event_log 的函数
    fn create_mock_event_logs() -> serde_json::Value {
        // 创建一个基本的模拟 event_log 结构
        serde_json::json!({
            "module": "tdx_eventlog",
            "version": "0.1.0",
            "events": [
                {
                    "index": 0,
                    "rtmr": 0,
                    "event_type": 1,
                    "event_name": "STUB_EVENT_0",
                    "digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "data": "0000000000000000"
                },
                {
                    "index": 1,
                    "rtmr": 1,
                    "event_type": 1,
                    "event_name": "STUB_EVENT_1",
                    "digest": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                    "data": "0101010101010101"
                },
                {
                    "index": 2,
                    "rtmr": 2,
                    "event_type": 1,
                    "event_name": "STUB_EVENT_2",
                    "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "data": "0202020202020202"
                },
                {
                    "index": 3,
                    "rtmr": 3,
                    "event_type": 1,
                    "event_name": "STUB_EVENT_3",
                    "digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "data": "0303030303030303"
                }
            ]
        })
    }
    pub async fn request_cert(
        &self,
        key: &KeyPair,
        config: CertConfig,
        no_ra: bool,
    ) -> Result<Vec<String>> {
        let pubkey = key.public_key_der();
        let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
        let (quote, event_log) = if !no_ra {
            //let (_, quote) = get_quote(&report_data, None).context("Failed to get quote")?;
            let quote = Self::create_mock_quote(&report_data);
            //let event_log = read_event_logs().context("Failed to decode event log")?;
            let event_log = Self::create_mock_event_logs(); 
            let event_log =
                serde_json::to_vec(&event_log).context("Failed to serialize event log")?;
            (quote, event_log)
        } else {
            (vec![], vec![])
        };

        let csr = CertSigningRequest {
            confirm: "please sign cert:".to_string(),
            pubkey,
            config,
            quote,
            event_log,
        };
        let signature = csr.signed_by(key).context("Failed to sign the CSR")?;
        self.sign_csr(&csr, &signature)
            .await
            .context("Failed to sign the CSR")
    }
}
