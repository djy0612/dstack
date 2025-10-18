use csv_attest_sys::*;

pub mod rtmr;

/// CSV 证明报告错误类型
#[derive(Debug, thiserror::Error)]
pub enum CsvAttestationError {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    #[error("Memory allocation failed")]
    MemoryAllocation,
    
    #[error("IOCTL operation failed: {0}")]
    IoctlFailed(i32),
    
    #[error("Hypercall failed: {0}")]
    HypercallFailed(i32),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Certificate chain verification failed: {0}")]
    CertChainFailed(String),
    
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    
    #[error("Unknown error: {0}")]
    Unknown(i32),

}

impl From<i32> for CsvAttestationError {
    fn from(error_code: i32) -> Self {
        match error_code {
            0 => unreachable!(), // CSV_SUCCESS
            CSV_ERROR_INVALID_PARAM => CsvAttestationError::InvalidParameter("Invalid parameter".to_string()),
            CSV_ERROR_MEMORY_ALLOC => CsvAttestationError::MemoryAllocation,
            CSV_ERROR_IOCTL_FAILED => CsvAttestationError::IoctlFailed(error_code),
            CSV_ERROR_HYPERCALL_FAILED => CsvAttestationError::HypercallFailed(error_code),
            CSV_ERROR_VERIFICATION_FAILED => CsvAttestationError::VerificationFailed("Verification failed".to_string()),
            CSV_ERROR_CERT_CHAIN_FAILED => CsvAttestationError::CertChainFailed("Certificate chain verification failed".to_string()),
            _ => CsvAttestationError::Unknown(error_code),
        }
    }
}

/// CSV 证明报告结果
pub type CsvAttestationResult<T> = Result<T, CsvAttestationError>;

/// CSV 证明报告结构体 - 使用官方 SDK 的类型
pub type CsvAttestationReport = csv_attest_sys::CsvAttestationReport;

// 使用官方 SDK 的 CsvAttestationReport 类型，无需自定义实现

/// CSV 证明客户端
pub struct CsvAttestationClient {
    nonce: [u8; GUEST_ATTESTATION_NONCE_SIZE as usize],
}

impl CsvAttestationClient {
    /// 创建新的 CSV 证明客户端
    pub fn new() -> Self {
        Self {
            nonce: [0u8; GUEST_ATTESTATION_NONCE_SIZE as usize],
        }
    }

    /// 生成随机数
    pub fn generate_nonce(&mut self) -> CsvAttestationResult<()> {
        let random_bytes = generate_random_bytes(GUEST_ATTESTATION_NONCE_SIZE as usize)?;
        self.nonce.copy_from_slice(&random_bytes);
        Ok(())
    }

    /// 设置自定义随机数
    pub fn set_nonce(&mut self, nonce: &[u8]) -> CsvAttestationResult<()> {
        if nonce.len() != GUEST_ATTESTATION_NONCE_SIZE as usize {
            return Err(CsvAttestationError::InvalidParameter(
                format!("Invalid nonce length: {} bytes", nonce.len())
            ));
        }
        self.nonce.copy_from_slice(nonce);
        Ok(())
    }

    /// 获取证明报告（通过 ioctl）
    pub fn get_attestation_report_ioctl(&self) -> CsvAttestationResult<CsvAttestationReport> {
        let mut report_buf = vec![0u8; std::mem::size_of::<CsvAttestationReport>()];
        
        let ret = unsafe {
            ioctl_get_attestation_report(
                report_buf.as_mut_ptr(),
                report_buf.len() as u32,
                self.nonce.as_ptr() as *mut u8,
                GUEST_ATTESTATION_NONCE_SIZE as u32,
            )
        };

        if ret == 0 {
            let report = unsafe {
                std::ptr::read(report_buf.as_ptr() as *const CsvAttestationReport)
            };
            Ok(report)
        } else {
            Err(ret.into())
        }
    }

    /// 获取证明报告（通过 vmmcall）
    pub fn get_attestation_report_vmmcall(&self) -> CsvAttestationResult<CsvAttestationReport> {
        let mut report_buf = vec![0u8; std::mem::size_of::<CsvAttestationReport>()];
        
        let ret = unsafe {
            vmmcall_get_attestation_report(
                report_buf.as_mut_ptr(),
                report_buf.len() as u32,
            )
        };

        if ret == 0 {
            let report = unsafe {
                std::ptr::read(report_buf.as_ptr() as *const CsvAttestationReport)
            };
            Ok(report)
        } else {
            Err(ret.into())
        }
    }

    /// 验证证明报告（支持完整证书链验证）
    pub fn verify_attestation_report(&self, report: &CsvAttestationReport, verify_chain: bool) -> CsvAttestationResult<()> {
        let mut report_bytes = self.report_to_bytes(report)?;
        
        let ret = unsafe {
            csv_attest_sys::verify_attestation_report(
                report_bytes.as_mut_ptr(),
                report_bytes.len() as u32,
                if verify_chain { 1 } else { 0 },
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(ret.into())
        }
    }

    /// 验证证书链（HRK → HSK → CEK → PEK）
    /// 使用官方 SDK 的 verify_attestation_report 函数，通过 verify_chain=true 参数实现
    pub fn verify_certificate_chain(&self, report: &CsvAttestationReport) -> CsvAttestationResult<()> {
        self.verify_attestation_report(report, true)
    }

    /// 将证明报告转换为字节数组
    fn report_to_bytes(&self, report: &CsvAttestationReport) -> CsvAttestationResult<Vec<u8>> {
        let size = std::mem::size_of::<CsvAttestationReport>();
        let mut bytes = Vec::with_capacity(size);
        
        unsafe {
            let ptr = report as *const CsvAttestationReport as *const u8;
            bytes.set_len(size);
            std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), size);
        }
        
        Ok(bytes)
    }
}

impl Default for CsvAttestationClient {
    fn default() -> Self {
        Self::new()
    }
}

/// 便捷函数：生成随机字节
pub fn generate_random_bytes(len: usize) -> CsvAttestationResult<Vec<u8>> {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    Ok(buf)
}

/// 便捷函数：验证证明报告
pub fn verify_attestation_report(report_data: &mut [u8], verify_chain: bool) -> CsvAttestationResult<()> {
    let ret = unsafe {
        csv_attest_sys::verify_attestation_report(
            report_data.as_mut_ptr(),
            report_data.len() as u32,
            if verify_chain { 1 } else { 0 },
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(ret.into())
    }
}

// 重新导出 RTMR 相关功能
pub use rtmr::{
    RtmrManager, RtmrValue,
    RTMR_COUNT, RTMR_SIZE,
    extend_rtmr3, get_rtmr_value, get_all_rtmr_values,
};
