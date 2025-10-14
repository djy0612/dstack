use crate::CsvAttestationError;
use cc_eventlog::TdxEventLog;
use fs_err as fs;
use serde::{Deserialize, Serialize};
use serde_human_bytes;
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use std::path::Path;

/// RTMR 寄存器索引
pub const RTMR_COUNT: usize = 4;

/// RTMR 寄存器值大小（48字节，SHA384）
pub const RTMR_SIZE: usize = 48;

/// 模拟的 RTMR 寄存器值
pub type RtmrValue = [u8; RTMR_SIZE];

/// RTMR 扩展事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtmrExtendEvent {
    /// RTMR 索引 (0-3)
    pub rtmr_index: u32,
    /// 事件类型
    pub event_type: u32,
    /// 扩展数据
    #[serde(with = "serde_human_bytes")]
    pub extend_data: [u8; RTMR_SIZE],
    /// 事件名称
    pub event_name: String,
    /// 事件载荷
    #[serde(with = "serde_human_bytes")]
    pub event_payload: Vec<u8>,
}

/// RTMR 管理器
pub struct RtmrManager {
    /// RTMR 寄存器值
    rtmr_values: [RtmrValue; RTMR_COUNT],
    /// RTMR 历史文件路径
    rtmr_file: String,
    /// 事件日志文件路径
    event_log_file: String,
}

impl RtmrManager {
    /// 创建新的 RTMR 管理器
    pub fn new() -> Self {
        Self {
            rtmr_values: [[0u8; RTMR_SIZE]; RTMR_COUNT],
            rtmr_file: "/run/log/csv_rtmr/rtmr_values.json".to_string(),
            event_log_file: "/run/log/csv_rtmr/rtmr_events.log".to_string(),
        }
    }

    /// 创建新的 RTMR 管理器，使用自定义文件路径
    pub fn with_paths(rtmr_file: String, event_log_file: String) -> Self {
        Self {
            rtmr_values: [[0u8; RTMR_SIZE]; RTMR_COUNT],
            rtmr_file,
            event_log_file,
        }
    }

    /// 从文件加载 RTMR 值
    pub fn load_from_file(&mut self) -> Result<(), CsvAttestationError> {
        if !Path::new(&self.rtmr_file).exists() {
            // 文件不存在，使用默认值
            return Ok(());
        }

        let data = fs::read_to_string(&self.rtmr_file)
            .map_err(|e| CsvAttestationError::Unknown(e.raw_os_error().unwrap_or(-1) as i32))?;

        let rtmr_data: HashMap<String, Vec<u8>> = serde_json::from_str(&data)
            .map_err(|_| CsvAttestationError::VerificationFailed("Failed to parse RTMR data".to_string()))?;

        for (key, value) in rtmr_data {
            if let Ok(index) = key.parse::<usize>() {
                if index < RTMR_COUNT && value.len() == RTMR_SIZE {
                    self.rtmr_values[index].copy_from_slice(&value);
                }
            }
        }

        Ok(())
    }

    /// 保存 RTMR 值到文件
    pub fn save_to_file(&self) -> Result<(), CsvAttestationError> {
        // 创建目录
        if let Some(parent) = Path::new(&self.rtmr_file).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| {
                    eprintln!("Failed to create directory {:?}: {}", parent, e);
                    CsvAttestationError::Unknown(e.raw_os_error().unwrap_or(-1) as i32)
                })?;
        }

        // 转换为 HashMap 格式
        let mut rtmr_data = HashMap::new();
        for (i, value) in self.rtmr_values.iter().enumerate() {
            rtmr_data.insert(i.to_string(), value.to_vec());
        }

        let data = serde_json::to_string_pretty(&rtmr_data)
            .map_err(|e| {
                eprintln!("Failed to serialize RTMR data: {}", e);
                CsvAttestationError::VerificationFailed(format!("Failed to serialize RTMR data: {}", e))
            })?;

        fs::write(&self.rtmr_file, data)
            .map_err(|e| {
                eprintln!("Failed to write RTMR file {:?}: {}", self.rtmr_file, e);
                CsvAttestationError::Unknown(e.raw_os_error().unwrap_or(-1) as i32)
            })?;

        Ok(())
    }

    /// 扩展 RTMR 寄存器
    pub fn extend_rtmr(&mut self, index: u32, event_type: u32, extend_data: [u8; RTMR_SIZE]) -> Result<(), CsvAttestationError> {
        if index as usize >= RTMR_COUNT {
            return Err(CsvAttestationError::InvalidParameter(
                format!("Invalid RTMR index: {}", index)
            ));
        }

        // 计算新的 RTMR 值：SHA384(current_value || extend_data)
        let mut hasher = Sha384::new();
        hasher.update(&self.rtmr_values[index as usize]);
        hasher.update(&extend_data);
        let new_value: RtmrValue = hasher.finalize().into();

        // 更新 RTMR 值
        self.rtmr_values[index as usize] = new_value;

        // 记录事件日志
        let event = RtmrExtendEvent {
            rtmr_index: index,
            event_type,
            extend_data,
            event_name: format!("RTMR{}_EXTEND", index),
            event_payload: extend_data.to_vec(),
        };

        self.log_rtmr_event(&event)?;

        // 保存到文件
        self.save_to_file()?;

        Ok(())
    }

    /// 获取 RTMR 值
    pub fn get_rtmr_value(&self, index: u32) -> Result<[u8; RTMR_SIZE], CsvAttestationError> {
        if index as usize >= RTMR_COUNT {
            return Err(CsvAttestationError::InvalidParameter(
                format!("Invalid RTMR index: {}", index)
            ));
        }

        Ok(self.rtmr_values[index as usize])
    }

    /// 获取所有 RTMR 值
    pub fn get_all_rtmr_values(&self) -> [RtmrValue; RTMR_COUNT] {
        self.rtmr_values
    }

    /// 记录 RTMR 事件到日志文件
    fn log_rtmr_event(&self, event: &RtmrExtendEvent) -> Result<(), CsvAttestationError> {
        // 创建目录
        if let Some(parent) = Path::new(&self.event_log_file).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| {
                    eprintln!("Failed to create directory {:?}: {}", parent, e);
                    CsvAttestationError::Unknown(e.raw_os_error().unwrap_or(-1) as i32)
                })?;
        }

        // 转换为 TdxEventLog 格式
        let event_log = TdxEventLog::new(
            event.rtmr_index,
            event.event_type,
            event.event_name.clone(),
            event.event_payload.clone(),
        );

        // 序列化并写入文件
        let log_line = serde_json::to_string(&event_log)
            .map_err(|e| {
                eprintln!("Failed to serialize event log: {}", e);
                CsvAttestationError::VerificationFailed(format!("Failed to serialize event log: {}", e))
            })?;

        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.event_log_file)
            .map_err(|e| {
                eprintln!("Failed to open event log file {:?}: {}", self.event_log_file, e);
                CsvAttestationError::Unknown(e.raw_os_error().unwrap_or(-1) as i32)
            })?;

        use std::io::Write;
        file.write_all(log_line.as_bytes())
            .map_err(|e| {
                eprintln!("Failed to write to event log file: {}", e);
                CsvAttestationError::Unknown(e.raw_os_error().unwrap_or(-1) as i32)
            })?;
        file.write_all(b"\n")
            .map_err(|e| {
                eprintln!("Failed to write newline to event log file: {}", e);
                CsvAttestationError::Unknown(e.raw_os_error().unwrap_or(-1) as i32)
            })?;

        Ok(())
    }

    /// 读取 RTMR 事件日志
    pub fn read_rtmr_event_logs(&self) -> Result<Vec<TdxEventLog>, CsvAttestationError> {
        if !Path::new(&self.event_log_file).exists() {
            return Ok(vec![]);
        }

        let data = fs::read_to_string(&self.event_log_file)
            .map_err(|e| CsvAttestationError::Unknown(e.raw_os_error().unwrap_or(-1) as i32))?;

        let mut event_logs = vec![];
        for line in data.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let event_log = serde_json::from_str::<TdxEventLog>(line)
                .map_err(|_| CsvAttestationError::VerificationFailed("Failed to parse event log".to_string()))?;
            event_logs.push(event_log);
        }

        Ok(event_logs)
    }

    /// 重置 RTMR 寄存器
    pub fn reset_rtmr(&mut self, index: u32) -> Result<(), CsvAttestationError> {
        if index as usize >= RTMR_COUNT {
            return Err(CsvAttestationError::InvalidParameter(
                format!("Invalid RTMR index: {}", index)
            ));
        }

        self.rtmr_values[index as usize] = [0u8; RTMR_SIZE];
        self.save_to_file()?;

        Ok(())
    }

    /// 重置所有 RTMR 寄存器
    pub fn reset_all_rtmr(&mut self) -> Result<(), CsvAttestationError> {
        self.rtmr_values = [[0u8; RTMR_SIZE]; RTMR_COUNT];
        self.save_to_file()?;

        Ok(())
    }
}

impl Default for RtmrManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 便捷函数：扩展 RTMR
pub fn extend_rtmr(index: u32, event_type: u32, extend_data: [u8; RTMR_SIZE]) -> Result<(), CsvAttestationError> {
    let mut manager = RtmrManager::new();
    manager.load_from_file()?;
    manager.extend_rtmr(index, event_type, extend_data)
}

/// 便捷函数：获取 RTMR 值
pub fn get_rtmr_value(index: u32) -> Result<[u8; RTMR_SIZE], CsvAttestationError> {
    let mut manager = RtmrManager::new();
    manager.load_from_file()?;
    manager.get_rtmr_value(index)
}

/// 便捷函数：获取所有 RTMR 值
pub fn get_all_rtmr_values() -> Result<[RtmrValue; RTMR_COUNT], CsvAttestationError> {
    let mut manager = RtmrManager::new();
    manager.load_from_file()?;
    Ok(manager.get_all_rtmr_values())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_rtmr_extend() {
        let mut manager = RtmrManager::new();
        
        // 测试扩展 RTMR0
        let extend_data = [1u8; RTMR_SIZE];
        manager.extend_rtmr(0, 1, extend_data).unwrap();
        
        // 验证值已更新
        let value = manager.get_rtmr_value(0).unwrap();
        assert_ne!(value, [0u8; RTMR_SIZE]);
        
        // 再次扩展
        let extend_data2 = [2u8; RTMR_SIZE];
        manager.extend_rtmr(0, 2, extend_data2).unwrap();
        
        // 验证值再次更新
        let value2 = manager.get_rtmr_value(0).unwrap();
        assert_ne!(value2, value);
    }

    #[test]
    fn test_rtmr_invalid_index() {
        let mut manager = RtmrManager::new();
        
        // 测试无效索引
        let extend_data = [1u8; RTMR_SIZE];
        let result = manager.extend_rtmr(4, 1, extend_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_rtmr_file_operations() {
        let temp_dir = tempdir().unwrap();
        let rtmr_file = temp_dir.path().join("rtmr_values.json");
        let event_log_file = temp_dir.path().join("rtmr_events.log");
        
        let mut manager = RtmrManager {
            rtmr_file: rtmr_file.to_string_lossy().to_string(),
            event_log_file: event_log_file.to_string_lossy().to_string(),
            ..Default::default()
        };
        
        // 扩展 RTMR
        let extend_data = [1u8; RTMR_SIZE];
        manager.extend_rtmr(0, 1, extend_data).unwrap();
        
        // 创建新管理器并加载
        let mut manager2 = RtmrManager {
            rtmr_file: rtmr_file.to_string_lossy().to_string(),
            event_log_file: event_log_file.to_string_lossy().to_string(),
            ..Default::default()
        };
        manager2.load_from_file().unwrap();
        
        // 验证值一致
        assert_eq!(manager.get_rtmr_value(0).unwrap(), manager2.get_rtmr_value(0).unwrap());
    }
}
