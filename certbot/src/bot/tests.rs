#![cfg(not(test))]

use instant_acme::LetsEncrypt;

use super::*;

async fn new_certbot() -> Result<CertBot> {
    let cf_zone_id = std::env::var("CLOUDFLARE_ZONE_ID").expect("CLOUDFLARE_ZONE_ID not set");
    let cf_api_token = std::env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN not set");
    let domains = vec![std::env::var("TEST_DOMAIN").expect("TEST_DOMAIN not set")];
    let config = CertBotConfig::builder()
        .acme_url(LetsEncrypt::Staging.url())
        .auto_create_account(true)
        .credentials_file("./test-workdir/credentials.json")
        .cf_zone_id(cf_zone_id)
        .cf_api_token(cf_api_token)
        .cert_dir("./test-workdir/backup")
        .cert_file("./test-workdir/live/cert.pem")
        .key_file("./test-workdir/live/key.pem")
        .cert_subject_alt_names(domains)
        .renew_interval(Duration::from_secs(30))
        .renew_timeout(Duration::from_secs(120))
        .renew_expires_in(Duration::from_secs(7772187))
        .auto_set_caa(false)
        .build();
    config.build_bot().await
}

#[tokio::test]
async fn test_certbot() {
    tracing_subscriber::fmt::try_init().ok();

    let bot = new_certbot().await.unwrap();
    bot.run().await;
}
