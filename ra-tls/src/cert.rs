//! Certificate creation functions.

use std::time::SystemTime;
use std::{path::Path, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use fs_err as fs;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
};
use ring::rand::SystemRandom;
use tdx_attest::eventlog::read_event_logs;
use tdx_attest::get_quote;
use x509_parser::der_parser::Oid;
use x509_parser::prelude::{FromDer as _, X509Certificate};
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::attestation::QuoteContentType;
use crate::oids::{PHALA_RATLS_APP_ID, PHALA_RATLS_CERT_USAGE};
use crate::{
    oids::{PHALA_RATLS_EVENT_LOG, PHALA_RATLS_QUOTE},
    traits::CertExt,
};
use ring::signature::{
    EcdsaKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING,
};
use scale::{Decode, Encode};

/// A CA certificate and private key.
pub struct CaCert {
    /// The original PEM certificate.
    pub pem_cert: String,
    /// CA certificate
    cert: Certificate,
    /// CA private key
    pub key: KeyPair,
}

impl CaCert {
    /// Instantiate a new CA certificate with a given private key and pem cert.
    pub fn new(pem_cert: String, pem_key: String) -> Result<Self> {
        let key = KeyPair::from_pem(&pem_key).context("Failed to parse key")?;
        let cert =
            CertificateParams::from_ca_cert_pem(&pem_cert).context("Failed to parse cert")?;
        let todo = "load the cert from the file directly: blocked by https://github.com/rustls/rcgen/issues/274";
        let cert = cert.self_signed(&key).context("Failed to self-sign cert")?;
        Ok(Self {
            pem_cert,
            cert,
            key,
        })
    }

    /// Instantiate a new CA certificate with a given private key and pem cert.
    pub fn from_parts(key: KeyPair, cert: Certificate) -> Self {
        Self {
            pem_cert: cert.pem(),
            cert,
            key,
        }
    }

    /// Load a CA certificate and private key from files.
    pub fn load(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self> {
        let pem_key = fs::read_to_string(key_path).context("Failed to read key file")?;
        let pem_cert = fs::read_to_string(cert_path).context("Failed to read cert file")?;
        Self::new(pem_cert, pem_key)
    }

    /// Sign a certificate request.
    pub fn sign(&self, req: CertRequest<impl PublicKeyData>) -> Result<Certificate> {
        req.signed_by(&self.cert, &self.key)
    }

    /// Sign a remote certificate signing request.
    pub fn sign_csr(
        &self,
        csr: &CertSigningRequest,
        app_id: Option<&[u8]>,
        usage: &str,
    ) -> Result<Certificate> {
        let pki = rcgen::SubjectPublicKeyInfo::from_der(&csr.pubkey)
            .context("Failed to parse signature")?;
        let cfg = &csr.config;
        let req = CertRequest::builder()
            .key(&pki)
            .subject(&cfg.subject)
            .maybe_org_name(cfg.org_name.as_deref())
            .alt_names(&cfg.subject_alt_names)
            .usage_server_auth(cfg.usage_server_auth)
            .usage_client_auth(cfg.usage_client_auth)
            .maybe_quote(cfg.ext_quote.then_some(&csr.quote))
            .maybe_event_log(cfg.ext_quote.then_some(&csr.event_log))
            .maybe_app_id(app_id)
            .special_usage(usage)
            .build();
        self.sign(req).context("Failed to sign certificate")
    }
}

/// The configuration of the certificate.
#[derive(Encode, Decode, Clone, PartialEq)]
pub struct CertConfig {
    /// The organization name of the certificate.
    pub org_name: Option<String>,
    /// The subject of the certificate.
    pub subject: String,
    /// The subject alternative names of the certificate.
    pub subject_alt_names: Vec<String>,
    /// The purpose of the certificate.
    pub usage_server_auth: bool,
    /// The purpose of the certificate.
    pub usage_client_auth: bool,
    /// Whether the certificate is quoted.
    pub ext_quote: bool,
}

/// A certificate signing request.
#[derive(Encode, Decode, Clone, PartialEq)]
pub struct CertSigningRequest {
    /// The confirm word, need to be "please sign cert:"
    pub confirm: String,
    /// The public key of the certificate.
    pub pubkey: Vec<u8>,
    /// The certificate configuration.
    pub config: CertConfig,
    /// The quote of the certificate.
    pub quote: Vec<u8>,
    /// The event log of the certificate.
    pub event_log: Vec<u8>,
}

impl CertSigningRequest {
    /// Sign the certificate signing request.
    pub fn signed_by(&self, key: &KeyPair) -> Result<Vec<u8>> {
        let encoded = self.encode();
        let rng = SystemRandom::new();
        // Extract the DER-encoded private key and create an ECDSA key pair
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key.serialize_der(), &rng)
                .context("Failed to create key pair from DER")?;

        // Sign the encoded CSR
        let signature = key_pair
            .sign(&rng, &encoded)
            .expect("Failed to sign CSR")
            .as_ref()
            .to_vec();
        Ok(signature)
    }

    /// Verify the signature of the certificate signing request.
    pub fn verify(&self, signature: &[u8]) -> Result<()> {
        let encoded = self.encode();
        let (_rem, pki) =
            SubjectPublicKeyInfo::from_der(&self.pubkey).context("Failed to parse pubkey")?;
        let parsed_pki = pki.parsed().context("Failed to parse pki")?;
        if !matches!(parsed_pki, PublicKey::EC(_)) {
            bail!("Unsupported algorithm");
        }
        let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &pki.subject_public_key.data);
        // verify signature
        key.verify(&encoded, signature)
            .ok()
            .context("Invalid signature")?;
        if self.confirm != "please sign cert:" {
            bail!("Invalid confirm word");
        }
        Ok(())
    }

    /// Encode the certificate signing request to a vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.encode()
    }
}

/// Information required to create a certificate.
#[derive(bon::Builder)]
pub struct CertRequest<'a, Key> {
    key: &'a Key,
    org_name: Option<&'a str>,
    subject: &'a str,
    alt_names: Option<&'a [String]>,
    ca_level: Option<u8>,
    app_id: Option<&'a [u8]>,
    special_usage: Option<&'a str>,
    quote: Option<&'a [u8]>,
    event_log: Option<&'a [u8]>,
    not_before: Option<SystemTime>,
    not_after: Option<SystemTime>,
    #[builder(default = false)]
    usage_server_auth: bool,
    #[builder(default = false)]
    usage_client_auth: bool,
}

impl<Key> CertRequest<'_, Key> {
    fn into_cert_params(self) -> Result<CertificateParams> {
        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();
        if let Some(org_name) = self.org_name {
            dn.push(DnType::OrganizationName, org_name);
        }
        dn.push(DnType::CommonName, self.subject);
        params.distinguished_name = dn;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        if self.usage_server_auth {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);
        }
        if self.usage_client_auth {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ClientAuth);
        }
        if let Some(alt_names) = self.alt_names {
            for alt_name in alt_names {
                params
                    .subject_alt_names
                    .push(SanType::DnsName(alt_name.clone().try_into()?));
            }
        }
        if let Some(quote) = self.quote {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(quote);
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_QUOTE, content);
            params.custom_extensions.push(ext);
        }
        if let Some(event_log) = self.event_log {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(event_log);
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_EVENT_LOG, content);
            params.custom_extensions.push(ext);
        }
        if let Some(app_id) = self.app_id {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(app_id);
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_APP_ID, content);
            params.custom_extensions.push(ext);
        }
        if let Some(special_usage) = self.special_usage {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(special_usage.as_bytes());
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_CERT_USAGE, content);
            params.custom_extensions.push(ext);
        }
        if let Some(ca_level) = self.ca_level {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(ca_level));
        }
        if let Some(not_before) = self.not_before {
            params.not_before = not_before.into();
        }
        params.not_after = self
            .not_after
            .unwrap_or_else(|| {
                let now = SystemTime::now();
                let day = Duration::from_secs(86400);
                now + day * 365 * 10
            })
            .into();
        Ok(params)
    }
}

impl CertRequest<'_, KeyPair> {
    /// Create a self-signed certificate.
    pub fn self_signed(self) -> Result<Certificate> {
        let key = self.key;
        let cert = self.into_cert_params()?.self_signed(key)?;
        Ok(cert)
    }
}

impl<Key: PublicKeyData> CertRequest<'_, Key> {
    /// Create a certificate signed by a given issuer.
    pub fn signed_by(self, issuer: &Certificate, issuer_key: &KeyPair) -> Result<Certificate> {
        let key = self.key;
        let cert = self
            .into_cert_params()?
            .signed_by(key, issuer, issuer_key)?;
        Ok(cert)
    }
}

impl CertExt for Certificate {
    fn get_extension_der(&self, oid: &[u64]) -> Result<Option<Vec<u8>>> {
        let found = self
            .params()
            .custom_extensions
            .iter()
            .find(|ext| ext.oid_components().collect::<Vec<_>>() == oid)
            .map(|ext| ext.content().to_vec());
        Ok(found)
    }
}

impl CertExt for X509Certificate<'_> {
    fn get_extension_der(&self, oid: &[u64]) -> Result<Option<Vec<u8>>> {
        let oid = Oid::from(oid).or(Err(anyhow!("Invalid oid")))?;
        let found = self
            .get_extension_unique(&oid)
            .context("failt to decode der")?
            .map(|ext| ext.value.to_vec());
        Ok(found)
    }
}

/// A key and certificate pair.
pub struct CertPair {
    /// The certificate in PEM format.
    pub cert_pem: String,
    /// The key in PEM format.
    pub key_pem: String,
}
fn create_mock_quote(report_data: &[u8]) -> Vec<u8> {  
    let quote_hex = "040002008100000000000000939a7233f79c4ca9940a0db3957f060783fbfe61525f55581315cd9dc950f44700000000060102000000000000000000000000005b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c436489d6c8e4f92f160b7cad34207b00c100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000e702060000000000c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000085e0855a6384fa1c8a6ab36d0dcbfaa11a5753e5a070c08218ae5fe872fcb86967fd2449c29e22e59dc9fec998cb65476ba8f87f35d0641e8abca07e75e3882abdc9f19d7cc8f6e3fe04435bd5f694d4e3cf008b60d7c7233896e8d1f23c34a703b1c4afcac07d00d8e853163aff3ba3f9af68ddfbdbeafab70210a8dc601b409c28873d74fb6dbe7dc33a8da7c096216d1a3da994b6611ee602f25f07b41671ece90cd2898689f1ad4448fdf1155e3668736cca4499659caae2d8044070de5700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cc1000004f8ed43bde5c1c75f4dcc530d5015ab0514879a8b9dc2663e6c462ac2a0a31face0b334f64976b2aadc4ec0acf00601d5f5738cbf61c12fdcc25dab524a9eac84996a9e56e40ac6c0b019709537f16d751c03e8c0d905d79f224ff06ddc4102860a8770107748c011cdbfcccc857e418735b699ac89dc2ed4da11d5125cb925e0600461000000202191b03ff0006000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000e700000000000000e5a3a7b5d830c2953b98534c6c59a3a34fdc34e933f7f5898f0a85cf08846bca0000000000000000000000000000000000000000000000000000000000000000dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000503bbfe5befa55a13e21747c3859f0b618a050312a0340e980187eea232356d60000000000000000000000000000000000000000000000000000000000000000784b1126be37912aaa4189f677ac8821e36366bb526c1b9ffc42c9ad0c332804423f05b854f20d4c511dbcaee26c5911e9b47d28b0f791b9c3d993554034b1382000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05005e0e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494538444343424a65674177494241674956414c5235544954392b396e73423142545a3173725851346c627752424d416f4743437147534d343942414d430a4d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d0a45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155450a4341774351304578437a414a42674e5642415954416c56544d423458445449304d4467774d6a45784d54557a4e316f5844544d784d4467774d6a45784d54557a0a4e316f77634445694d434147413155454177775a535735305a5777675530645949464244537942445a584a3061575a70593246305a5445614d426747413155450a43677752535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d517377435159440a5651514944414a445154454c4d416b474131554542684d4356564d775754415442676371686b6a4f5051494242676771686b6a4f50514d4242774e43414154590a77777155344778504a6a596f6a4d4752686136327970346a425164355744764b776d54366c6c314147786a59363870694a50676950686462387a544766374b620a314f79643153464f4d5a70594c795054427a59646f3449444444434341776777487759445652306a42426777466f41556c5739647a62306234656c4153636e550a3944504f4156634c336c5177617759445652306642475177596a42676f46366758495a616148523063484d364c79396863476b7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253397a5a3367765932567964476c6d61574e6864476c76626939324e4339775932746a636d772f593245390a6347786864475a76636d306d5a57356a62325270626d63395a4756794d423047413155644467515742425146303476507654474b7762416c356f54765664664d0a2b356a6e7554414f42674e56485138424166384542414d434273417744415944565230544151482f4241497741444343416a6b4743537147534962345451454e0a4151534341696f776767496d4d42344743697147534962345451454e41514545454e3564416f7135634b356e383277396f793165346e34776767466a42676f710a686b69472b453042445145434d494942557a415142677371686b69472b4530424451454341514942416a415142677371686b69472b45304244514543416749420a416a415142677371686b69472b4530424451454341774942416a415142677371686b69472b4530424451454342414942416a415142677371686b69472b4530420a4451454342514942417a415142677371686b69472b45304244514543426749424154415142677371686b69472b453042445145434277494241444151426773710a686b69472b4530424451454343414942417a415142677371686b69472b45304244514543435149424144415142677371686b69472b45304244514543436749420a4144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69472b4530420a44514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b453042445145434477494241444151426773710a686b69472b45304244514543454149424144415142677371686b69472b4530424451454345514942437a416642677371686b69472b45304244514543456751510a4167494341674d4241414d4141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b453042445145450a4241617777473841414141774477594b4b6f5a496876684e4151304242516f424154416542676f71686b69472b453042445145474242424a316472685349736d0a682b2f46793074746a6a762f4d45514743697147534962345451454e415163774e6a415142677371686b69472b45304244514548415145422f7a4151426773710a686b69472b45304244514548416745422f7a415142677371686b69472b45304244514548417745422f7a414b42676771686b6a4f5051514441674e48414442450a41694270455738754f726b537469486b4c4b6e6a426855416f637a39545733366a4e2f303765416844503635617749674d2f31474c58745a70446436706150760a535a386d4e7472543830305635346b465944474f7a4f78504374383d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";  
      
    let mut quote = hex::decode(quote_hex.trim()).expect("Invalid hex");  
      
    // 检查quote长度  
    if quote.len() < 632 {  
        panic!("Quote is too short, need at least 632 bytes");  
    }  
      
    // 使用正确的偏移量568而不是576  
    let report_data_offset = 568;  
    let mut padded_report_data = [0u8; 64];  
    let copy_len = std::cmp::min(report_data.len(), 64);  
    padded_report_data[..copy_len].copy_from_slice(&report_data[..copy_len]);  
      
    // 替换report_data到正确位置  
    quote[report_data_offset..report_data_offset + 64]  
        .copy_from_slice(&padded_report_data);  
      
    quote  
}



// 添加一个创建模拟 event_log 的函数
fn create_mock_event_logs() -> serde_json::Value {  
    // 直接返回 event log 数组，而不是包装在对象中  
    serde_json::json!([{"imr":0,"event_type":2147483659u32,"digest":"0e35f1b315ba6c912cf791e5c79dd9d3a2b8704516aa27d4e5aa78fb09ede04aef2bbd02ac7a8734c48562b9c26ba35d","event":"","event_payload":"095464785461626c65000100000000000000af96bb93f2b9b84e9462e0ba745642360090800000000000"},{"imr":0,"event_type":2147483658u32,"digest":"344bc51c980ba621aaa00da3ed7436f7d6e549197dfe699515dfa2c6583d95e6412af21c097d473155875ffd561d6790","event":"","event_payload":"2946762858585858585858582d585858582d585858582d585858582d58585858585858585858585829000000c0ff000000000040080000000000"},{"imr":0,"event_type":2147483649u32,"digest":"9dc3a1f80bcec915391dcda5ffbb15e7419f77eab462bbf72b42166fb70d50325e37b36f93537a863769bcf9bedae6fb","event":"","event_payload":"61dfe48bca93d211aa0d00e098032b8c0a00000000000000000000000000000053006500630075007200650042006f006f007400"},{"imr":0,"event_type":2147483649u32,"digest":"6f2e3cbc14f9def86980f5f66fd85e99d63e69a73014ed8a5633ce56eca5b64b692108c56110e22acadcef58c3250f1b","event":"","event_payload":"61dfe48bca93d211aa0d00e098032b8c0200000000000000000000000000000050004b00"},{"imr":0,"event_type":2147483649u32,"digest":"d607c0efb41c0d757d69bca0615c3a9ac0b1db06c557d992e906c6b7dee40e0e031640c7bfd7bcd35844ef9edeadc6f9","event":"","event_payload":"61dfe48bca93d211aa0d00e098032b8c030000000000000000000000000000004b0045004b00"},{"imr":0,"event_type":2147483649u32,"digest":"08a74f8963b337acb6c93682f934496373679dd26af1089cb4eaf0c30cf260a12e814856385ab8843e56a9acea19e127","event":"","event_payload":"cbb219d73a3d9645a3bcdad00e67656f0200000000000000000000000000000064006200"},{"imr":0,"event_type":2147483649u32,"digest":"18cc6e01f0c6ea99aa23f8a280423e94ad81d96d0aeb5180504fc0f7a40cb3619dd39bd6a95ec1680a86ed6ab0f9828d","event":"","event_payload":"cbb219d73a3d9645a3bcdad00e67656f03000000000000000000000000000000640062007800"},{"imr":0,"event_type":4,"digest":"394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0","event":"","event_payload":"00000000"},{"imr":0,"event_type":10,"digest":"68cd79315e70aecd4afe7c1b23a5ed7b3b8e51a477e1739f111b3156def86bbc56ebf239dcd4591bc7a9fff90023f481","event":"","event_payload":"414350492044415441"},{"imr":0,"event_type":10,"digest":"6bc203b3843388cc4918459c3f5c6d1300a796fb594781b7ecfaa3ae7456975f095bfcc1156c9f2d25e8b8bc1b520f66","event":"","event_payload":"414350492044415441"},{"imr":0,"event_type":10,"digest":"ec9e8622a100c399d71062a945f95d8e4cdb7294e8b1c6d17a6a8d37b5084444000a78b007ef533f290243421256d25c","event":"","event_payload":"414350492044415441"},{"imr":1,"event_type":2147483651u32,"digest":"0db5964580e727672734da95797318d8455ab74b3e3d66fbb1aaa4ddd01a3f8555f4889e57c19a15c165594e31678dc0","event":"","event_payload":"18a0447b0000000000b4b2000000000000000000000000002a000000000000000403140072f728144ab61e44b8c39ebdd7f893c7040412006b00650072006e0065006c0000007fff0400"},{"imr":0,"event_type":2147483650u32,"digest":"1dd6f7b457ad880d840d41c961283bab688e94e4b59359ea45686581e90feccea3c624b1226113f824f315eb60ae0a7c","event":"","event_payload":"61dfe48bca93d211aa0d00e098032b8c0900000000000000020000000000000042006f006f0074004f0072006400650072000000"},{"imr":0,"event_type":2147483650u32,"digest":"23ada07f5261f12f34a0bd8e46760962d6b4d576a416f1fea1c64bc656b1d28eacf7047ae6e967c58fd2a98bfa74c298","event":"","event_payload":"61dfe48bca93d211aa0d00e098032b8c08000000000000003e0000000000000042006f006f0074003000300030003000090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400"},{"imr":1,"event_type":2147483655u32,"digest":"77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71","event":"","event_payload":"43616c6c696e6720454649204170706c69636174696f6e2066726f6d20426f6f74204f7074696f6e"},{"imr":1,"event_type":4,"digest":"394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0","event":"","event_payload":"00000000"},{"imr":2,"event_type":6,"digest":"ad49ca7e80258d7580c5c580cd21ada7ecbf418dde5197d6f8c835493ceb6edec0f8954b733bd9b889f96f33e5f9cb05","event":"","event_payload":"ed223b8f1a0000004c4f414445445f494d4147453a3a4c6f61644f7074696f6e7300"},{"imr":2,"event_type":6,"digest":"e0cdb72fbba75a0f4d396c0b80a4336db049b383a9730467160dec0b7059cb22aca87639dcc655d935d6c6356b3108ad","event":"","event_payload":"ec223b8f0d0000004c696e757820696e6974726400"},{"imr":1,"event_type":2147483655u32,"digest":"214b0bef1379756011344877743fdc2a5382bac6e70362d624ccf3f654407c1b4badf7d8f9295dd3dabdef65b27677e0","event":"","event_payload":"4578697420426f6f7420536572766963657320496e766f636174696f6e"},{"imr":1,"event_type":2147483655u32,"digest":"0a2e01c85deae718a530ad8c6d20a84009babe6c8989269e950d8cf440c6e997695e64d455c4174a652cd080f6230b74","event":"","event_payload":"4578697420426f6f742053657276696365732052657475726e656420776974682053756363657373"},{"imr":3,"event_type":134217729u32,"digest":"f9974020ef507068183313d0ca808e0d1ca9b2d1ad0c61f5784e7157c362c06536f5ddacdad4451693f48fcc72fff624","event":"system-preparing","event_payload":""},{"imr":3,"event_type":134217729u32,"digest":"b01c7a2e6a406ae9cd5aa81451e4614e112b8f404df12e6ef506962c1a5279a94dc58da0923c4b7db89e26da9e538302","event":"app-id","event_payload":"ea549f02e1a25fabd1cb788380e033ec5461b2ff"},{"imr":3,"event_type":134217729u32,"digest":"9c1fecc259af1e8494484a391bdef460cb74d677c76dd114b1e9e7fac343da4e773b2b0eb8df7a6fc0dd8ba5edbb30e1","event":"compose-hash","event_payload":"ea549f02e1a25fabd1cb788380e033ec5461b2ffe4328d753642cf035452e48b"},{"imr":3,"event_type":134217729u32,"digest":"a8dc2d07060d74dfba7b4942411bcf93ae198da42d172860f0c6dcb9207198a2c857a4b0e57bb019d68be072074a2d01","event":"instance-id","event_payload":"59df8036b824b0aac54f8998b9e1fb2a0cfc5d3a"},{"imr":3,"event_type":134217729u32,"digest":"98bd7e6bd3952720b65027fd494834045d06b4a714bf737a06b874638b3ea00ff402f7f583e3e3b05e921c8570433ac6","event":"boot-mr-done","event_payload":""},{"imr":3,"event_type":134217729u32,"digest":"cc0ae424f1335f3059359f712f72f0aebee7a01fba2e4d527f3ea9299bac808a3ea1f8ae2982875fb3c9697fd6f4a5f2","event":"key-provider","event_payload":"7b226e616d65223a226b6d73222c226964223a223330353933303133303630373261383634386365336430323031303630383261383634386365336430333031303730333432303030343139623234353764643962386161363434366439383066313336666666373831326563643663373737343065656230653238623130643536633063303030323861356236653539646365613330376435383362643166373037363965396331313664663262636662313735386139356438363133653764653163383438326330227d"},{"imr":3,"event_type":134217729u32,"digest":"1a76b2a80a0be71eae59f80945d876351a7a3fb8e9fd1ff1cede5734aa84ea11fd72b4edfbb6f04e5a85edd114c751bd","event":"system-ready","event_payload":""}]
)  
}
/// Generate a certificate with RA-TLS quote and event log.
pub fn generate_ra_cert(ca_cert_pem: String, ca_key_pem: String) -> Result<CertPair> {
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let ca = CaCert::new(ca_cert_pem, ca_key_pem)?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    //let (_, quote) = get_quote(&report_data, None).context("Failed to get quote")?;
    let quote = create_mock_quote(&report_data);
    //let event_logs = read_event_logs().context("Failed to read event logs")?;
    let event_logs = create_mock_event_logs(); 
    let event_log = serde_json::to_vec(&event_logs).context("Failed to serialize event logs")?;
    let req = CertRequest::builder()
        .subject("RA-TLS TEMP Cert")
        .quote(&quote)
        .event_log(&event_log)
        .key(&key)
        .build();
    let cert = ca.sign(req).context("Failed to sign certificate")?;
    Ok(CertPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PKCS_ECDSA_P256_SHA256;

    #[test]
    fn test_csr_signing_and_verification() {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let pubkey = key_pair.public_key_der();

        let csr = CertSigningRequest {
            confirm: "please sign cert:".to_string(),
            pubkey: pubkey.clone(),
            config: CertConfig {
                org_name: Some("Test Org".to_string()),
                subject: "test.example.com".to_string(),
                subject_alt_names: vec!["alt.example.com".to_string()],
                usage_server_auth: true,
                usage_client_auth: false,
                ext_quote: false,
            },
            quote: Vec::new(),
            event_log: Vec::new(),
        };

        let signature = csr.signed_by(&key_pair).unwrap();
        assert!(csr.verify(&signature).is_ok());

        let mut invalid_signature = signature.clone();
        invalid_signature[0] ^= 0xff;
        assert!(csr.verify(&invalid_signature).is_err());
    }

    #[test]
    fn test_invalid_confirm_word() {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let pubkey = key_pair.public_key_der();

        let csr = CertSigningRequest {
            confirm: "wrong confirm word".to_string(),
            pubkey: pubkey.clone(),
            config: CertConfig {
                org_name: Some("Test Org".to_string()),
                subject: "test.example.com".to_string(),
                subject_alt_names: vec![],
                usage_server_auth: true,
                usage_client_auth: false,
                ext_quote: false,
            },
            quote: Vec::new(),
            event_log: Vec::new(),
        };

        let signature = csr.signed_by(&key_pair).unwrap();
        assert!(csr.verify(&signature).is_err());
    }
}
