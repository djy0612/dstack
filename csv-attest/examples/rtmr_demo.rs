use csv_attest::{CsvAttestationClient, extend_rtmr3, get_rtmr_value, get_all_rtmr_values, RtmrManager};
use std::path::PathBuf;
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CSV RTMR 模拟演示");
    println!("==================");

    // 创建临时目录用于测试
    let temp_dir = tempdir()?;
    let temp_path = temp_dir.path();
    
    println!("使用临时目录: {:?}", temp_path);

    // 创建 CSV 证明客户端
    let mut client = CsvAttestationClient::new();
    client.generate_nonce()?;
    println!("✓ 生成随机数成功");

    // 创建 RTMR 管理器，使用临时目录
    let mut rtmr_manager = RtmrManager::with_paths(
        temp_path.join("rtmr_values.json").to_string_lossy().to_string(),
        temp_path.join("rtmr_events.log").to_string_lossy().to_string(),
    );
    rtmr_manager.load_from_file()?;
    println!("✓ 加载 RTMR 管理器成功");

    // 演示 RTMR 扩展
    println!("\n--- RTMR 扩展演示 ---");
    
    // 扩展 RTMR3 - 事件1
    let extend_data1 = [1u8; 48];
    rtmr_manager.extend_rtmr_with_event(3, 0x08000001, "event1", &extend_data1)?;
    println!("✓ 扩展 RTMR3 事件1 成功");

    // 扩展 RTMR3 - 事件2
    let extend_data2 = [2u8; 48];
    rtmr_manager.extend_rtmr_with_event(3, 0x08000001, "event2", &extend_data2)?;
    println!("✓ 扩展 RTMR3 事件2 成功");

    // 再次扩展 RTMR3 - 事件3
    let extend_data3 = [3u8; 48];
    rtmr_manager.extend_rtmr_with_event(3, 0x08000001, "event3", &extend_data3)?;
    println!("✓ 再次扩展 RTMR3 事件3 成功");

    // 读取 RTMR 值
    println!("\n--- RTMR 值读取 ---");
    let rtmr0_value = rtmr_manager.get_rtmr_value(0)?;
    let rtmr1_value = rtmr_manager.get_rtmr_value(1)?;
    
    println!("RTMR0 值: {}", hex::encode(rtmr0_value));
    println!("RTMR1 值: {}", hex::encode(rtmr1_value));

    // 读取所有 RTMR 值
    let all_values = rtmr_manager.get_all_rtmr_values();
    println!("\n所有 RTMR 值:");
    for (i, value) in all_values.iter().enumerate() {
        if value.iter().any(|&x| x != 0) {
            println!("  RTMR{}: {}", i, hex::encode(value));
        }
    }

    // 读取事件日志
    println!("\n--- 事件日志读取 ---");
    let event_logs = rtmr_manager.read_rtmr_event_logs()?;
    println!("事件日志数量: {}", event_logs.len());
    
    for (i, log) in event_logs.iter().enumerate() {
        println!("  事件 {}: IMR={}, 类型={}, 事件={}", 
                i, log.imr, log.event_type, log.event);
    }

    // 演示便捷函数（注意：便捷函数使用默认路径，可能无法访问临时目录）
    println!("\n--- 便捷函数演示 ---");
    println!("注意：便捷函数使用默认路径，可能无法访问临时目录");
    
    // 创建一个新的管理器用于便捷函数测试
    let mut temp_manager = RtmrManager::new();
    
    // 使用管理器扩展 RTMR3
    let extend_data4 = [4u8; 48];
    temp_manager.extend_rtmr_with_event(3, 0x08000001, "temp-event", &extend_data4)?;
    println!("✓ 使用管理器扩展 RTMR3 成功");

    // 使用管理器读取 RTMR3
    let rtmr3_value = temp_manager.get_rtmr_value(3)?;
    println!("RTMR3 值: {}", hex::encode(rtmr3_value));

    // 使用管理器读取所有 RTMR 值
    let all_values = temp_manager.get_all_rtmr_values();
    println!("\n使用管理器读取所有 RTMR 值:");
    for (i, value) in all_values.iter().enumerate() {
        if value.iter().any(|&x| x != 0) {
            println!("  RTMR{}: {}", i, hex::encode(value));
        }
    }

    println!("\n✓ RTMR 模拟演示完成！");
    Ok(())
}
