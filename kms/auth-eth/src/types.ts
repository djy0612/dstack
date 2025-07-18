export interface BootInfo {
  tcbStatus: string;        // TCB（可信计算基础）状态
  advisoryIds: string[];    // 安全建议 ID 列表
  mrAggregated: string;     // 聚合度量寄存器值
  mrSystem: string;         // 系统度量寄存器值
  osImageHash: string;      // 操作系统镜像哈希值
  appId: string;            // 应用程序 ID
  composeHash: string;      // Docker Compose 配置哈希
  instanceId: string;       // 实例 ID
  deviceId: string;         // 设备 ID
}

export interface BootResponse {
  isAllowed: boolean;       // 是否被授权启动
  gatewayAppId: string;     // 网关应用 ID
  reason: string;           // 授权/拒绝的原因
}

// Removed KMS_CONTRACT_ABI and APP_CONTRACT_ABI since we're using typechain types now
