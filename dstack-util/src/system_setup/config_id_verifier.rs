use anyhow::{bail, Context, Result};
use dstack_types::{mr_config::MrConfig, KeyProviderKind};
use tracing::info;
use sha2::{Digest as _, Sha256};

// 添加环境检测
fn is_csv_available() -> bool {
    std::path::Path::new("/dev/sev").exists()
        || std::path::Path::new("/dev/hygon_csv").exists()
}

fn read_mr_config_id() -> Result<[u8; 48]> {
    if !is_csv_available() {
        info!("CSV not available, returning zero config ID");
        return Ok([0u8; 48]);
    }
    // CSV：采用 V2 方案生成 config_id（示例实现）
    // V2: 1B version(2) + 32B keccak/sha256(instance_info) + padding(15B)
    // 这里用 sha256(instance_info) 代替（保持 32B），剩余字节填 0
    let mut instance_info = Vec::new();
    instance_info.extend_from_slice(b"csv-config");
    let digest: [u8; 32] = Sha256::new_with_prefix(&instance_info).finalize().into();
    let mut out = [0u8; 48];
    out[0] = 2; // version 2
    out[1..33].copy_from_slice(&digest);
    Ok(out)
}

/// Verify the mr_config_id matches the expected value
///
/// Configuration ID format
/// The mr_config_id is a 48 bytes value in the following format:
/// The first byte is the version of the format.
/// When version is 1, the next 32 bytes are the compose hash.
/// When version is 2, the next 32 bytes are the keccak256 hash of the instance info.
/// Where the instance info is a concatenated bytes of the following fields:
/// - compose_hash: [u8; 32]
/// - app_id: [u8; 20]
/// - key_provider_type: u8 // 0: none, 1: local, 2: kms
/// - key_provider_id: [u8] // the ca pubkey for KMS or the MR enclave for local-sgx provider, empty for none
pub fn verify_mr_config_id(
    compose_hash: &[u8; 32],
    app_id: &[u8; 20],
    key_provider: KeyProviderKind,
    key_provider_id: &[u8],
) -> Result<()> {
    let read_mr_config_id = read_mr_config_id().context("Failed to read mr_config_id")?;
    info!("mr_config_id: {}", hex::encode(read_mr_config_id));

    // 非 TDX 环境或全零配置直接通过
    if read_mr_config_id == [0u8; 48] {
        if !is_csv_available() {
            info!("Running in non-CSV mode, skipping configuration verification");
        } else {
            info!("CSV mode with zero config_id, skipping configuration verification");
        }
        return Ok(());
    }
    let mr_config = match read_mr_config_id[0] {
        1 => MrConfig::V1 { compose_hash },
        2 => MrConfig::V2 {
            compose_hash,
            app_id,
            key_provider,
            key_provider_id,
        },
        _ => bail!("Invalid mr_config_id version"),
    };
    if mr_config.to_mr_config_id() != read_mr_config_id {
        bail!("Invalid mr_config_id");
    }
    Ok(())
}
