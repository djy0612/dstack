use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use config::KmsConfig;
use main_service::{KmsState, RpcHandler};
use ra_rpc::rocket_helper::QuoteVerifier;
use rocket::{
    fairing::AdHoc,
    figment::{providers::Serialized, Figment},
    response::content::RawHtml,
    Shutdown,
};
use tracing::{info, warn};
//引入四个模块
mod config;
// mod ct_log;
mod crypto;
mod main_service;
mod onboard_service;

// 返回版本信息 
fn app_version() -> String {
    const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
    const VERSION: &str = git_version::git_version!(
        args = ["--abbrev=20", "--always", "--dirty=-modified"],
        prefix = "git:",
        fallback = "unknown"
    );
    format!("v{CARGO_PKG_VERSION} ({VERSION})")
}

// 定义命令行参数
#[derive(Parser)]
#[command(author, version, about, long_version = app_version())]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
}

// 负责启动 KMS 的引导服务
async fn run_onboard_service(kms_config: KmsConfig, figment: Figment) -> Result<()> {
    use onboard_service::{OnboardHandler, OnboardState};

    // 定义路由,当访问根路径时返回 onboard.html 文件内容
    #[rocket::get("/")]
    async fn index() -> RawHtml<&'static str> {
        RawHtml(include_str!("www/onboard.html"))
    }

    // 定义路由,当访问 /finish 时触发关闭通知
    #[rocket::get("/finish")]
    fn finish(shutdown: Shutdown) -> &'static str {
        shutdown.notify();
        "OK"
    }

    // 检查是否启用自动引导域
    if !kms_config.onboard.auto_bootstrap_domain.is_empty() {
        onboard_service::bootstrap_keys(&kms_config).await?;
        return Ok(());
    }

    // 初始化引导状态
    let state = OnboardState::new(kms_config);
    let figment = figment
        .clone()
        .merge(Serialized::defaults(figment.find_value("core.onboard")?));

    // Remove section tls

    // 创建一个自定义的 Rocket 实例
    let _ = rocket::custom(figment)
        // 将根路径 / 的路由挂载到 index 和 finish 函数
        .mount("/", rocket::routes![index, finish])
        // 将 /prpc 路径的路由挂载到 OnboardState 和 OnboardHandler，并去除 Onboard. 前缀
        .mount(
            "/prpc",
            ra_rpc::prpc_routes!(OnboardState, OnboardHandler, trim: "Onboard."),
        )
        // 将 state 管理对象传递给 rocket，以便在处理请求时可以访问
        .manage(state)
        // 启动 rocket 服务，并等待其完成
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

#[rocket::main]
async fn main() -> Result<()> {
    // 初始化日志系统
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }
    // 解析命令行参数
    let args = Args::parse();
    // 加载配置文件
    let figment = config::load_config_figment(args.config.as_deref());
    let config: KmsConfig = figment.focus("core").extract()?;
    // 如果 config.onboard.enabled 为 true 且密钥尚未初始化则启动引导服务
    if config.onboard.enabled && !config.keys_exists() {
        info!("Onboarding");
        run_onboard_service(config.clone(), figment.clone()).await?;
        if !config.keys_exists() {
            bail!("Failed to onboard");
        }
    }
    // 更新证书
    info!("Updating certs");
    if let Err(err) = onboard_service::update_certs(&config).await {
        warn!("Failed to update certs: {err}");
    };
    
    // 启动 KMS 服务
    info!("Starting KMS");
    info!("Supported methods:");
    // 打印支持的 RPC 方法
    for method in main_service::rpc_methods() {
        info!("  /prpc/{method}");
    }

    // 创建 KmsState 实例
    let state = main_service::KmsState::new(config).context("Failed to initialize KMS state")?;
    // 使用 figment 配置创建一个自定义的 rocket 实例
    let figment = figment
        .clone()
        .merge(Serialized::defaults(figment.find_value("rpc")?));

    let mut rocket = rocket::custom(figment)
        // 添加自定义响应头 X-App-Version。
        .attach(AdHoc::on_response("Add app version header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        // 挂载 /prpc 路由到 KmsState 和 RpcHandler
        .mount(
            "/prpc",
            ra_rpc::prpc_routes!(KmsState, RpcHandler, trim: "KMS."),
        )
        .manage(state);
    // 添加 QuoteVerifier 管理对象
    // CSV 验证不依赖 PCCS
    let verifier = QuoteVerifier::new(None);
    rocket = rocket.manage(verifier);

    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
