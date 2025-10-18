use anyhow::{Context, Result};
use bollard::container::{ListContainersOptions, RemoveContainerOptions};
use bollard::Docker;
use clap::{Parser, Subcommand};
use dstack_types::KeyProvider;
use fs_err as fs;
use getrandom::fill as getrandom;
use host_api::HostApi;
use k256::schnorr::SigningKey;
use ra_tls::{
    attestation::QuoteContentType,
    cert::generate_ra_cert,
    kdf::{derive_ecdsa_key, derive_ecdsa_key_pair_from_bytes},
    rcgen::KeyPair,
};
use scale::Decode;
use serde::Deserialize;
use std::{collections::HashMap, path::Path};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
use system_setup::{cmd_sys_setup, SetupArgs};
use csv_attest as att;
use utils::AppKeys;

mod crypto;
mod host_api;
mod parse_env_file;
mod system_setup;
mod utils;

/// DStack guest utility
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Get TDX report given report data from stdin
    Report,
    /// Generate a TDX quote given report data from stdin
    Quote,
    /// Extend RTMRs
    Extend(ExtendArgs),
    /// Show the current RTMR state
    Show,
    /// Hex encode data
    Hex(HexCommand),
    /// Generate a RA-TLS certificate
    GenRaCert(GenRaCertArgs),
    /// Generate a CA certificate
    GenCaCert(GenCaCertArgs),
    /// Generate app keys for an dstack app
    GenAppKeys(GenAppKeysArgs),
    /// Generate random data
    Rand(RandArgs),
    /// Prepare dstack system.
    Setup(SetupArgs),
    /// Notify the host about the dstack app
    NotifyHost(HostNotifyArgs),
    /// Remove orphaned containers
    RemoveOrphans(RemoveOrphansArgs),
}

#[derive(Parser)]
/// Hex encode data
struct HexCommand {
    #[clap(value_parser)]
    /// filename to hex encode
    filename: Option<String>,
}

#[derive(Parser)]
/// Extend RTMR
struct ExtendArgs {
    #[clap(short, long)]
    /// event name
    event: String,

    #[clap(short, long)]
    /// hex encoded payload of the event
    payload: String,
}

#[derive(Parser)]
/// Generate a certificate
struct GenRaCertArgs {
    /// CA certificate used to sign the RA certificate
    #[arg(long)]
    ca_cert: PathBuf,

    /// CA private key used to sign the RA certificate
    #[arg(long)]
    ca_key: PathBuf,

    #[arg(short, long)]
    /// file path to store the certificate
    cert_path: PathBuf,

    #[arg(short, long)]
    /// file path to store the private key
    key_path: PathBuf,
}

#[derive(Parser)]
/// Generate CA certificate
struct GenCaCertArgs {
    /// path to store the certificate
    #[arg(long)]
    cert: PathBuf,
    /// path to store the private key
    #[arg(long)]
    key: PathBuf,
    /// CA level
    #[arg(long, default_value_t = 1)]
    ca_level: u8,
}

#[derive(Parser)]
/// Generate app keys
struct GenAppKeysArgs {
    /// CA level
    #[arg(long, default_value_t = 1)]
    ca_level: u8,

    /// path to store the app keys
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Parser)]
/// Generate random data
struct RandArgs {
    /// number of bytes to generate
    #[arg(short = 'n', long, default_value_t = 20)]
    bytes: usize,

    /// output to file
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// hex encode output
    #[arg(short = 'x', long)]
    hex: bool,
}

#[derive(Parser)]
/// Test app feature. Print "true" if the feature is supported, otherwise print "false".
struct TestAppFeatureArgs {
    /// path to the app keys
    #[arg(short, long)]
    feature: String,

    /// path to the app compose file
    #[arg(short, long)]
    compose: String,
}

#[derive(Parser)]
/// Notify the host about the dstack app
struct HostNotifyArgs {
    #[arg(short, long)]
    url: Option<String>,
    /// event name
    #[arg(short, long)]
    event: String,
    /// event payload
    #[arg(short = 'd', long)]
    payload: String,
}

#[derive(Parser)]
/// Remove orphaned containers
struct RemoveOrphansArgs {
    /// path to the docker-compose.yaml file
    #[arg(short = 'f', long)]
    compose: String,
}

#[derive(Debug, Deserialize)]
struct ComposeConfig {
    name: Option<String>,
    services: HashMap<String, ComposeService>,
}

#[derive(Debug, Deserialize)]
struct ComposeService {}

fn cmd_quote() -> Result<()> {
    // 读取 report_data（CSV 驱动不会使用此参数）
    let mut _report_data = [0; 64];
    let _ = io::stdin().read_exact(&mut _report_data);

    let mut client = csv_attest::CsvAttestationClient::new();
    client.generate_nonce().context("Failed to generate nonce")?;
    let report = client
        .get_attestation_report_ioctl()
        .or_else(|_| client.get_attestation_report_vmmcall())
        .context("Failed to get CSV attestation report")?;

    let size = core::mem::size_of_val(&report);
    let mut quote = Vec::with_capacity(size);
    unsafe {
        quote.set_len(size);
        core::ptr::copy_nonoverlapping(
            &report as *const _ as *const u8,
            quote.as_mut_ptr(),
            size,
        );
    }
    io::stdout()
        .write_all(&quote)
        .context("Failed to write quote")?;
    Ok(())
}

fn cmd_extend(extend_args: ExtendArgs) -> Result<()> {
    let payload = hex::decode(&extend_args.payload).context("Failed to decode payload")?;
    att::rtmr::extend_rtmr3(&extend_args.event, &payload).context("Failed to extend RTMR")
}

fn cmd_report() -> Result<()> {
    let mut report_data = [0; 64];
    io::stdin()
        .read_exact(&mut report_data)
        .context("Failed to read report data")?;
    // CSV: 无 get_report，直接输出传入的 report_data 作为占位
    io::stdout()
        .write_all(&report_data)
        .context("Failed to write report data")?;
    Ok(())
}

fn cmd_rand(rand_args: RandArgs) -> Result<()> {
    let mut data = vec![0u8; rand_args.bytes];
    getrandom(&mut data).context("Failed to generate random data")?;
    if rand_args.hex {
        data = hex::encode(data).into_bytes();
    }
    io::stdout()
        .write_all(&data)
        .context("Failed to write random data")?;
    Ok(())
}

#[derive(Decode)]
struct ParsedReport {
    attributes: [u8; 8],
    xfam: [u8; 8],
    mrtd: [u8; 48],
    mrconfigid: [u8; 48],
    mrowner: [u8; 48],
    mrownerconfig: [u8; 48],
    rtmr0: [u8; 48],
    rtmr1: [u8; 48],
    rtmr2: [u8; 48],
    rtmr3: [u8; 48],
    servtd_hash: [u8; 48],
}

impl core::fmt::Debug for ParsedReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use hex_fmt::HexFmt as HF;

        f.debug_struct("ParsedReport")
            .field("attributes", &HF(&self.attributes))
            .field("xfam", &HF(&self.xfam))
            .field("mrtd", &HF(&self.mrtd))
            .field("mrconfigid", &HF(&self.mrconfigid))
            .field("mrowner", &HF(&self.mrowner))
            .field("mrownerconfig", &HF(&self.mrownerconfig))
            .field("rtmr0", &HF(&self.rtmr0))
            .field("rtmr1", &HF(&self.rtmr1))
            .field("rtmr2", &HF(&self.rtmr2))
            .field("rtmr3", &HF(&self.rtmr3))
            .field("servtd_hash", &HF(&self.servtd_hash))
            .finish()
    }
}

fn cmd_show_mrs() -> Result<()> {
    let attestation = ra_tls::attestation::Attestation::local()?;
    let app_info = attestation.decode_app_info(false)?;
    serde_json::to_writer_pretty(io::stdout(), &app_info)?;
    println!();
    Ok(())
}

fn cmd_hex(hex_args: HexCommand) -> Result<()> {
    fn hex_encode_io(io: &mut impl Read) -> Result<()> {
        loop {
            let mut buf = [0; 1024];
            let n = io.read(&mut buf).context("Failed to read from stdin")?;
            if n == 0 {
                break;
            }
            print!("{}", hex_fmt::HexFmt(&buf[..n]));
        }
        Ok(())
    }
    if let Some(filename) = hex_args.filename {
        let mut input =
            fs::File::open(&filename).context(format!("Failed to open {}", filename))?;
        hex_encode_io(&mut input)?;
    } else {
        hex_encode_io(&mut io::stdin())?;
    };
    Ok(())
}

fn cmd_gen_ra_cert(args: GenRaCertArgs) -> Result<()> {
    let ca_cert = fs::read_to_string(args.ca_cert)?;
    let ca_key = fs::read_to_string(args.ca_key)?;
    let cert_pair = generate_ra_cert(ca_cert, ca_key)?;
    fs::write(&args.cert_path, cert_pair.cert_pem).context("Failed to write certificate")?;
    fs::write(&args.key_path, cert_pair.key_pem).context("Failed to write private key")?;
    Ok(())
}

fn cmd_gen_ca_cert(args: GenCaCertArgs) -> Result<()> {
    use ra_tls::cert::CertRequest;
    use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::KmsRootCa.to_report_data(&pubkey);
    // CSV: 获取原始报告字节
    let mut client = csv_attest::CsvAttestationClient::new();
    client.generate_nonce().context("Failed to generate nonce")?;
    let report = client
        .get_attestation_report_ioctl()
        .or_else(|_| client.get_attestation_report_vmmcall())
        .context("Failed to get CSV attestation report")?;
    let size = core::mem::size_of_val(&report);
    let mut quote = Vec::with_capacity(size);
    unsafe {
        quote.set_len(size);
        core::ptr::copy_nonoverlapping(
            &report as *const _ as *const u8,
            quote.as_mut_ptr(),
            size,
        );
    }
    let event_logs = cc_eventlog::read_event_logs().context("Failed to read event logs1")?;
    let event_log = serde_json::to_vec(&event_logs).context("Failed to serialize event logs")?;

    let req = CertRequest::builder()
        .subject("App Root CA")
        .quote(&quote)
        .event_log(&event_log)
        .key(&key)
        .ca_level(args.ca_level)
        .build();

    let cert = req
        .self_signed()
        .context("Failed to self-sign certificate")?;
    fs::write(&args.cert, cert.pem()).context("Failed to write certificate")?;
    fs::write(&args.key, key.serialize_pem()).context("Failed to write private key")?;
    Ok(())
}

fn cmd_gen_app_keys(args: GenAppKeysArgs) -> Result<()> {
    use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let disk_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let k256_key = SigningKey::random(&mut rand::thread_rng());
    let app_keys = make_app_keys(key, disk_key, k256_key, args.ca_level, None)?;
    let app_keys = serde_json::to_string(&app_keys).context("Failed to serialize app keys")?;
    fs::write(&args.output, app_keys).context("Failed to write app keys")?;
    Ok(())
}

fn gen_app_keys_from_seed(seed: &[u8], mr: Option<Vec<u8>>) -> Result<AppKeys> {
    let key = derive_ecdsa_key_pair_from_bytes(seed, &["app-key".as_bytes()])?;
    let disk_key = derive_ecdsa_key_pair_from_bytes(seed, &["app-disk-key".as_bytes()])?;
    let k256_key = derive_ecdsa_key(seed, &["app-k256-key".as_bytes()], 32)?;
    let k256_key = SigningKey::from_bytes(&k256_key).context("Failed to parse k256 key")?;
    make_app_keys(key, disk_key, k256_key, 1, mr)
}

fn create_mock_quote(report_data: &[u8]) -> Vec<u8> {
    // 直接把 quote.hex 的完整内容写到代码里
    // ⚠️ 请把下面的 "ab12cd34..." 替换为 quote.hex 的完整十六进制字符串
    let quote_hex = "\
        040002008100000000000000939a7233f79c4ca9940a0db3957f060783fbfe61525f55581315cd9dc950f44700000000060102000000000000000000000000005b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c436489d6c8e4f92f160b7cad34207b00c100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000e702060000000000c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000085e0855a6384fa1c8a6ab36d0dcbfaa11a5753e5a070c08218ae5fe872fcb86967fd2449c29e22e59dc9fec998cb65476ba8f87f35d0641e8abca07e75e3882abdc9f19d7cc8f6e3fe04435bd5f694d4e3cf008b60d7c7233896e8d1f23c34a703b1c4afcac07d00d8e853163aff3ba3f9af68ddfbdbeafab70210a8dc601b409c28873d74fb6dbe7dc33a8da7c096216d1a3da994b6611ee602f25f07b41671ece90cd2898689f1ad4448fdf1155e3668736cca4499659caae2d8044070de5700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cc1000004f8ed43bde5c1c75f4dcc530d5015ab0514879a8b9dc2663e6c462ac2a0a31face0b334f64976b2aadc4ec0acf00601d5f5738cbf61c12fdcc25dab524a9eac84996a9e56e40ac6c0b019709537f16d751c03e8c0d905d79f224ff06ddc4102860a8770107748c011cdbfcccc857e418735b699ac89dc2ed4da11d5125cb925e0600461000000202191b03ff0006000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000e700000000000000e5a3a7b5d830c2953b98534c6c59a3a34fdc34e933f7f5898f0a85cf08846bca0000000000000000000000000000000000000000000000000000000000000000dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000503bbfe5befa55a13e21747c3859f0b618a050312a0340e980187eea232356d60000000000000000000000000000000000000000000000000000000000000000784b1126be37912aaa4189f677ac8821e36366bb526c1b9ffc42c9ad0c332804423f05b854f20d4c511dbcaee26c5911e9b47d28b0f791b9c3d993554034b1382000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05005e0e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494538444343424a65674177494241674956414c5235544954392b396e73423142545a3173725851346c627752424d416f4743437147534d343942414d430a4d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d0a45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155450a4341774351304578437a414a42674e5642415954416c56544d423458445449304d4467774d6a45784d54557a4e316f5844544d784d4467774d6a45784d54557a0a4e316f77634445694d434147413155454177775a535735305a5777675530645949464244537942445a584a3061575a70593246305a5445614d426747413155450a43677752535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d517377435159440a5651514944414a445154454c4d416b474131554542684d4356564d775754415442676371686b6a4f5051494242676771686b6a4f50514d4242774e43414154590a77777155344778504a6a596f6a4d4752686136327970346a425164355744764b776d54366c6c314147786a59363870694a50676950686462387a544766374b620a314f79643153464f4d5a70594c795054427a59646f3449444444434341776777487759445652306a42426777466f41556c5739647a62306234656c4153636e550a3944504f4156634c336c5177617759445652306642475177596a42676f46366758495a616148523063484d364c79396863476b7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253397a5a3367765932567964476c6d61574e6864476c76626939324e4339775932746a636d772f593245390a6347786864475a76636d306d5a57356a62325270626d63395a4756794d423047413155644467515742425146303476507654474b7762416c356f54765664664d0a2b356a6e7554414f42674e56485138424166384542414d434273417744415944565230544151482f4241497741444343416a6b4743537147534962345451454e0a4151534341696f776767496d4d42344743697147534962345451454e41514545454e3564416f7135634b356e383277396f793165346e34776767466a42676f710a686b69472b453042445145434d494942557a415142677371686b69472b4530424451454341514942416a415142677371686b69472b45304244514543416749420a416a415142677371686b69472b4530424451454341774942416a415142677371686b69472b4530424451454342414942416a415142677371686b69472b4530420a4451454342514942417a415142677371686b69472b45304244514543426749424154415142677371686b69472b453042445145434277494241444151426773710a686b69472b4530424451454343414942417a415142677371686b69472b45304244514543435149424144415142677371686b69472b45304244514543436749420a4144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69472b4530420a44514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b453042445145434477494241444151426773710a686b69472b45304244514543454149424144415142677371686b69472b4530424451454345514942437a416642677371686b69472b45304244514543456751510a4167494341674d4241414d4141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b453042445145450a4241617777473841414141774477594b4b6f5a496876684e4151304242516f424154416542676f71686b69472b453042445145474242424a316472685349736d0a682b2f46793074746a6a762f4d45514743697147534962345451454e415163774e6a415142677371686b69472b45304244514548415145422f7a4151426773710a686b69472b45304244514548416745422f7a415142677371686b69472b45304244514548417745422f7a414b42676771686b6a4f5051514441674e48414442450a41694270455738754f726b537469486b4c4b6e6a426855416f637a39545733366a4e2f303765416844503635617749674d2f31474c58745a70446436706150760a535a386d4e7472543830305635346b465944474f7a4f78504374383d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
    ";

    // 转换为字节
    let mut quote = hex::decode(quote_hex).expect("Invalid hex");

    // 确保 report_data 正确写入 offset 576
    let report_data_offset = 576;
    let mut padded_report_data = [0u8; 64];
    let copy_len = std::cmp::min(report_data.len(), 64);
    padded_report_data[..copy_len].copy_from_slice(&report_data[..copy_len]);

    // 替换 report_data
    quote[report_data_offset..report_data_offset + 64]
        .copy_from_slice(&padded_report_data);

    quote
}


// 添加一个创建模拟 event_log 的函数
fn create_mock_event_logs() -> serde_json::Value {  
    // 直接返回 event log 数组，而不是包装在对象中  
    serde_json::json!([  
        {  
            "imr": 0,  
            "event_type": 2147483659u32,  
            "digest": "0e35f1b315ba6c912cf791e5c79dd9d3a2b8704516aa27d4e5aa78fb09ede04aef2bbd02ac7a8734c48562b9c26ba35d",  
            "event": "",  
            "event_payload": "095464785461626c65000100000000000000af96bb93f2b9b84e9462e0ba745642360090800000000000"  
        },  
        {  
            "imr": 0,  
            "event_type": 2147483658u32,  
            "digest": "344bc51c980ba621aaa00da3ed7436f7d6e549197dfe699515dfa2c6583d95e6412af21c097d473155875ffd561d6790",  
            "event": "",  
            "event_payload": "2946762858585858585858582d585858582d585858582d585858582d58585858585858585858585829000000c0ff000000000040080000000000"  
        },  
        {  
            "imr": 3,  
            "event_type": 134217729u32,  
            "digest": "f9974020ef507068183313d0ca808e0d1ca9b2d1ad0c61f5784e7157c362c06536f5ddacdad4451693f48fcc72fff624",  
            "event": "system-preparing",  
            "event_payload": ""  
        },  
        {  
            "imr": 3,  
            "event_type": 134217729u32,  
            "digest": "b01c7a2e6a406ae9cd5aa81451e4614e112b8f404df12e6ef506962c1a5279a94dc58da0923c4b7db89e26da9e538302",  
            "event": "app-id",  
            "event_payload": "0946dc4504cF03be26068A3C5248120f5065AA6F"  
        },  
        {  
            "imr": 3,  
            "event_type": 134217729u32,  
            "digest": "9c1fecc259af1e8494484a391bdef460cb74d677c76dd114b1e9e7fac343da4e773b2b0eb8df7a6fc0dd8ba5edbb30e1",  
            "event": "compose-hash",  
            "event_payload": "ea549f02e1a25fabd1cb788380e033ec5461b2ffe4328d753642cf035452e48b"  
        },  
        {  
            "imr": 3,  
            "event_type": 134217729u32,  
            "digest": "a8dc2d07060d74dfba7b4942411bcf93ae198da42d172860f0c6dcb9207198a2c857a4b0e57bb019d68be072074a2d01",  
            "event": "instance-id",  
            "event_payload": "59df8036b824b0aac54f8998b9e1fb2a0cfc5d3a"  
        },  
        {  
            "imr": 3,  
            "event_type": 134217729u32,  
            "digest": "98bd7e6bd3952720b65027fd494834045d06b4a714bf737a06b874638b3ea00ff402f7f583e3e3b05e921c8570433ac6",  
            "event": "boot-mr-done",  
            "event_payload": ""  
        },  
        {  
            "imr": 3,  
            "event_type": 134217729u32,  
            "digest": "cc0ae424f1335f3059359f712f72f0aebee7a01fba2e4d527f3ea9299bac808a3ea1f8ae2982875fb3c9697fd6f4a5f2",  
            "event": "key-provider",  
            "event_payload": "7b226e616d65223a226b6d73222c226964223a223330353933303133303630373261383634386365336430323031303630383261383634386365336430333031303730333432303030343139623234353764643962386161363434366439383066313336666666373831326563643663373737343065656230653238623130643536633063303030323861356236653539646365613330376435383362643166373037363965396331313664663262636662313735386139356438363133653764653163383438326330"  
        },  
        {  
            "imr": 3,  
            "event_type": 134217729u32,  
            "digest": "1a76b2a80a0be71eae59f80945d876351a7a3fb8e9fd1ff1cede5734aa84ea11fd72b4edfbb6f04e5a85edd114c751bd",  
            "event": "system-ready",  
            "event_payload": ""  
        }  
    ])  
}
fn make_app_keys(
    app_key: KeyPair,
    disk_key: KeyPair,
    k256_key: SigningKey,
    ca_level: u8,
    mr: Option<Vec<u8>>,
) -> Result<AppKeys> {
    use ra_tls::cert::CertRequest;
    let pubkey = app_key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    // 使用真实 CSV 报告
    let mut csv_client = csv_attest::CsvAttestationClient::new();
    csv_client.generate_nonce().context("Failed to generate nonce")?;
    let csv_report = csv_client
        .get_attestation_report_ioctl()
        .or_else(|_| csv_client.get_attestation_report_vmmcall())
        .context("Failed to get CSV attestation report")?;
    let size = core::mem::size_of_val(&csv_report);
    let mut quote = Vec::with_capacity(size);
    unsafe {
        quote.set_len(size);
        core::ptr::copy_nonoverlapping(
            &csv_report as *const _ as *const u8,
            quote.as_mut_ptr(),
            size,
        );
    }

    // 使用真实事件日志
    let event_logs = cc_eventlog::read_event_logs().context("Failed to read event logs")?;
    let event_log = serde_json::to_vec(&event_logs).context("Failed to serialize event logs")?;
    let req = CertRequest::builder()
        .subject("App Root Cert")
        .quote(&quote)
        .event_log(&event_log)
        .key(&app_key)
        .ca_level(ca_level)
        .build();
    let cert = req
        .self_signed()
        .context("Failed to self-sign certificate")?;

    Ok(AppKeys {
        disk_crypt_key: sha256(&disk_key.serialize_der()).to_vec(),
        env_crypt_key: vec![],
        k256_key: k256_key.to_bytes().to_vec(),
        k256_signature: vec![],
        gateway_app_id: "".to_string(),
        ca_cert: cert.pem(),
        key_provider: match mr {
            Some(mr) => KeyProvider::Local {
                mr,
                key: app_key.serialize_pem(),
            },
            None => KeyProvider::None {
                key: app_key.serialize_pem(),
            },
        },
    })
}

async fn cmd_notify_host(args: HostNotifyArgs) -> Result<()> {
    let client = HostApi::load_or_default(args.url)?;
    client.notify(&args.event, &args.payload).await?;
    Ok(())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut sha256 = sha2::Sha256::new();
    sha256.update(data);
    sha256.finalize().into()
}

fn get_project_name(compose_file: impl AsRef<Path>) -> Result<String> {
    let project_name = fs::canonicalize(compose_file)
        .context("Failed to canonicalize compose file")?
        .parent()
        .context("Failed to get parent directory of compose file")?
        .file_name()
        .context("Failed to get file name of compose file")?
        .to_string_lossy()
        .into_owned();
    Ok(project_name)
}

async fn cmd_remove_orphans(compose_file: impl AsRef<Path>) -> Result<()> {
    // Connect to Docker daemon
    let docker =
        Docker::connect_with_local_defaults().context("Failed to connect to Docker daemon")?;

    // Read and parse docker-compose.yaml to get project name
    let compose_content =
        fs::read_to_string(compose_file.as_ref()).context("Failed to read docker-compose.yaml")?;
    let docker_compose: ComposeConfig =
        serde_yaml2::from_str(&compose_content).context("Failed to parse docker-compose.yaml")?;

    // Get current project name from compose file or directory name
    let project_name = match docker_compose.name {
        Some(name) => name,
        None => get_project_name(compose_file)?,
    };

    // List all containers
    let options = ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };

    let containers = docker
        .list_containers(Some(options))
        .await
        .context("Failed to list containers")?;

    // Find and remove orphaned containers
    for container in containers {
        let Some(labels) = container.labels else {
            continue;
        };

        // Check if container belongs to current project
        let Some(container_project) = labels.get("com.docker.compose.project") else {
            continue;
        };

        if container_project != &project_name {
            continue;
        }
        // Check if service still exists in compose file
        let Some(service_name) = labels.get("com.docker.compose.service") else {
            continue;
        };
        if docker_compose.services.contains_key(service_name) {
            continue;
        }
        // Service no longer exists in compose file, remove the container
        let Some(container_id) = container.id else {
            continue;
        };

        println!("Removing orphaned container {service_name} {container_id}");
        docker
            .remove_container(
                &container_id,
                Some(RemoveContainerOptions {
                    v: true,
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .with_context(|| format!("Failed to remove container {}", container_id))?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Report => cmd_report()?,
        Commands::Quote => cmd_quote()?,
        Commands::Show => cmd_show_mrs()?,
        Commands::Extend(extend_args) => {
            cmd_extend(extend_args)?;
            //todo!("Extend command is currently disabled"); 
        }
        Commands::Hex(hex_args) => {
            cmd_hex(hex_args)?;
        }
        Commands::GenRaCert(args) => {
            cmd_gen_ra_cert(args)?;
        }
        Commands::Rand(rand_args) => {
            cmd_rand(rand_args)?;
        }
        Commands::GenCaCert(args) => {
            cmd_gen_ca_cert(args)?;
        }
        Commands::GenAppKeys(args) => {
            cmd_gen_app_keys(args)?;
        }
        Commands::Setup(args) => {
            cmd_sys_setup(args).await?;
        }
        Commands::NotifyHost(args) => {
            cmd_notify_host(args).await?;
        }
        Commands::RemoveOrphans(args) => {
            cmd_remove_orphans(args.compose).await?;
        }
    }

    Ok(())
}
