// 包含生成的绑定
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// 重新导出关键类型和函数
pub use crate::{
    csv_attestation_report as CsvAttestationReport,
    csv_attestation_user_data as CsvAttestationUserData,
    csv_guest_mem as CsvGuestMem,
    hash_block_u as HashBlockU,
    hash_block_t as HashBlock,
    chip_key_id_t as ChipKeyId,
    userid_u as UserIdU,
    ecc_pubkey_t as EccPubkey,
    ecc_signature_t as EccSignature,
    CSV_CERT_t as CsvCert,
};

// 为兼容性提供类型别名
pub type ChipRootCert = CSV_CERT_t;

// 官方 SDK 函数已通过 bindgen 自动生成，无需手动重新导出