# CSV 证明系统测试 Makefile

.PHONY: all test clean build install help

# 默认目标
all: build test

# 帮助信息
help:
	@echo "CSV Attestation System Test Makefile"
	@echo "===================================="
	@echo ""
	@echo "可用目标:"
	@echo "  build     - 编译所有组件"
	@echo "  test      - 运行所有测试"
	@echo "  quick     - 快速测试"
	@echo "  host-test - 主机环境测试（编译和基础功能）"
	@echo "  demo      - 运行示例程序"
	@echo "  clean     - 清理编译文件"
	@echo "  install   - 安装到系统"
	@echo "  env-check - 检查环境"
	@echo "  help      - 显示此帮助信息"
	@echo ""

# 编译所有组件
build:
	@echo "🔨 编译 CSV 证明系统组件..."
	cd ../csv-attest-sys && cargo build --release
	cd ../csv-attest && cargo build --release
	@echo "✅ 编译完成"

# 运行所有测试
test:
	@echo "🧪 运行所有测试..."
	cd ../csv-attest-sys && cargo test
	cd ../csv-attest && cargo test
	@echo "✅ 测试完成"

# 快速测试
quick:
	@echo "⚡ 快速测试..."
	@if [ -f scripts/quick_test.sh ]; then \
		bash scripts/quick_test.sh; \
	else \
		echo "快速测试脚本不存在，运行基础测试..."; \
		cargo test; \
	fi

# 主机环境测试
host-test:
	@echo "🖥️  主机环境测试..."
	@if [ -f scripts/host_test.sh ]; then \
		bash scripts/host_test.sh; \
	else \
		echo "主机测试脚本不存在，运行基础测试..."; \
		make build && make test; \
	fi

# 运行示例程序
demo:
	@echo "🎯 运行示例程序..."
	cd csv-attest && cargo run --example csv_attest_demo

# 环境检查
env-check:
	@echo "🔍 检查测试环境..."
	@echo "Rust 版本:"
	@rustc --version || echo "Rust 未安装"
	@echo ""
	@echo "Cargo 版本:"
	@cargo --version || echo "Cargo 未安装"
	@echo ""
	@echo "内核模块状态:"
	@lsmod | grep csv || echo "CSV 内核模块未加载"
	@echo ""
	@echo "设备文件状态:"
	@ls -la /dev/csv-guest 2>/dev/null || echo "CSV 设备文件不存在"
	@echo ""
	@echo "网络连接测试:"
	@curl -s --connect-timeout 5 https://kds.hygon.cn/hrk.cert > /dev/null && echo "KDS 服务可访问" || echo "KDS 服务不可访问"

# 清理编译文件
clean:
	@echo "🧹 清理编译文件..."
	cd csv-attest-sys && cargo clean
	cd csv-attest && cargo clean
	@echo "✅ 清理完成"

# 安装到系统
install:
	@echo "📦 安装到系统..."
	cd csv-attest-sys && cargo install --path .
	cd csv-attest && cargo install --path .
	@echo "✅ 安装完成"

# 性能测试
benchmark:
	@echo "📊 运行性能测试..."
	cd csv-attest && cargo run --bin performance_test

# 代码检查
check:
	@echo "🔍 代码检查..."
	cd csv-attest-sys && cargo check
	cd csv-attest && cargo check
	@echo "✅ 代码检查完成"

# 格式化代码
fmt:
	@echo "🎨 格式化代码..."
	cd csv-attest-sys && cargo fmt
	cd csv-attest && cargo fmt
	@echo "✅ 代码格式化完成"

# 文档生成
doc:
	@echo "📚 生成文档..."
	cd csv-attest-sys && cargo doc --no-deps
	cd csv-attest && cargo doc --no-deps
	@echo "✅ 文档生成完成"

# 发布构建
release:
	@echo "🚀 发布构建..."
	cd csv-attest-sys && cargo build --release
	cd csv-attest && cargo build --release
	@echo "✅ 发布构建完成"

# 集成测试
integration-test:
	@echo "🔗 集成测试..."
	@echo "测试内核模块..."
	@sudo modprobe csv-guest || echo "无法加载 CSV 内核模块"
	@echo "测试设备文件..."
	@ls -la /dev/csv-guest || echo "CSV 设备文件不存在"
	@echo "运行示例程序..."
	cd csv-attest && cargo run --example csv_attest_demo
	@echo "✅ 集成测试完成"
