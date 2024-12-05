//! Integration tests
use crate::server::start_server;
use rcgen::CertificateParams;
use rstest::rstest;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::sign::SigningKey;
use rustls::{CipherSuite, SignatureScheme, SupportedCipherSuite};
use rustls_cng_crypto::{custom_provider, default_provider};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use webpki::types::pem::PemObject as _;
use webpki::types::{CertificateDer, PrivateKeyDer};
use webpki::EndEntityCert;

pub mod server;

fn test_with_provider(
    provider: CryptoProvider,
    port: u16,
    root_ca_certs: Vec<CertificateDer<'static>>,
) -> CipherSuite {
    // Add default webpki roots to the root store
    let mut root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    root_store.add_parsable_certificates(root_ca_certs);

    #[allow(unused_mut)]
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = "localhost".try_into().unwrap();

    let mut sock = TcpStream::connect(format!("localhost:{port}")).unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: localhost\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

    let mut exit_buffer: [u8; 1] = [0]; // Size 1 because "q" is a single byte command
    exit_buffer[0] = b'q'; // Assign the ASCII value of "q" to the buffer

    // Write the "q" command to the TLS connection stream
    tls.write_all(&exit_buffer).unwrap();
    ciphersuite.suite()
}

#[rstest]
#[case::tls13_aes_128_gcm_sha256(
    rustls_cng_crypto::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls_cng_crypto::kx_group::SECP384R1,
    server::Alg::PKCS_ECDSA_P256_SHA256,
    CipherSuite::TLS13_AES_128_GCM_SHA256
)]
#[case::tls13_aes_256_gcm_sha384(
    rustls_cng_crypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls_cng_crypto::kx_group::SECP256R1,
    server::Alg::PKCS_ECDSA_P256_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[cfg_attr(
    feature = "tls12",
    case::tls_ecdhe_rsa_with_aes_256_gcm_sha384(
        rustls_cng_crypto::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls_cng_crypto::kx_group::SECP256R1,
        server::Alg::PKCS_RSA_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    )
)]
#[cfg_attr(
    feature = "tls12",
    case::tls_ecdhe_rsa_with_aes_128_gcm_sha256(
        rustls_cng_crypto::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        rustls_cng_crypto::kx_group::SECP256R1,
        server::Alg::PKCS_RSA_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    )
)]
#[case::tls13_aes_256_gcm_sha384_x25519(
    rustls_cng_crypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls_cng_crypto::kx_group::X25519,
    server::Alg::PKCS_ECDSA_P256_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[case::tls13_aes_256_gcm_sha384_secp384r1(
    rustls_cng_crypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls_cng_crypto::kx_group::SECP384R1,
    server::Alg::PKCS_ECDSA_P256_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[cfg_attr(
    feature = "tls12",
    case::tls_ecdhe_rsa_with_chacha20_poly1305_sha256(
        rustls_cng_crypto::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        rustls_cng_crypto::kx_group::SECP256R1,
        server::Alg::PKCS_RSA_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    )
)]
#[cfg_attr(
    feature = "tls12",
    case::tls_ecdhe_ecdsa_with_aes_128_gcm_sha256(
        rustls_cng_crypto::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls_cng_crypto::kx_group::SECP256R1,
        server::Alg::PKCS_ECDSA_P256_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    )
)]
// #[cfg_attr(
//     feature = "tls12",
//     case::ed25519_tls12(
//         rustls_cng_crypto::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
//         rustls_cng_crypto::kx_group::SECP256R1,
//         server::Alg::PKCS_ED25519,
//         CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
//     )
// )]
#[cfg_attr(
    feature = "tls12",
    case::tls_ecdhe_rsa_with_aes_256_gcm_sha384(
        rustls_cng_crypto::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls_cng_crypto::kx_group::X25519,
        server::Alg::PKCS_RSA_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    )
)]
#[case::tls13_aes_256_gcm_sha384_secp384r1(
    rustls_cng_crypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls_cng_crypto::kx_group::SECP384R1,
    server::Alg::PKCS_RSA_SHA512,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
fn test_client_and_server(
    #[case] suite: SupportedCipherSuite,
    #[case] group: &'static dyn SupportedKxGroup,
    #[case] alg: server::Alg,
    #[case] expected: CipherSuite,
) {
    // Run against a server using our default provider
    let (port, certificate) = start_server(alg);
    let provider = custom_provider(vec![suite], vec![group]);
    let actual_suite = test_with_provider(provider, port, vec![certificate]);
    assert_eq!(actual_suite, expected);
}

#[rstest]
#[cfg_attr(
    feature = "tls12",
    case(
        rustls_cng_crypto::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        rustls_cng_crypto::kx_group::SECP384R1,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    )
)]
#[case::tls13_aes_256_gcm_sha384(
    rustls_cng_crypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls_cng_crypto::kx_group::SECP384R1,
    CipherSuite::TLS13_AES_256_GCM_SHA384
)]
fn test_to_internet(
    #[case] suite: SupportedCipherSuite,
    #[case] group: &'static dyn SupportedKxGroup,
    #[case] expected: CipherSuite,
) {
    let cipher_suites = vec![suite];
    let kx_group = vec![group];

    // Add default webpki roots to the root store
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    #[allow(unused_mut)]
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(custom_provider(
        cipher_suites,
        kx_group,
    )))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let server_name = "index.crates.io".try_into().unwrap();
    let mut sock = TcpStream::connect("index.crates.io:443").unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(
        concat!(
            "GET /config.json HTTP/1.1\r\n",
            "Host: index.crates.io\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf).contains("https://static.crates.io/crates"));

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

    let mut exit_buffer: [u8; 1] = [0]; // Size 1 because "Q" is a single byte command
    exit_buffer[0] = b'q'; // Assign the ASCII value of "Q" to the buffer

    // Write the "Q" command to the TLS connection stream
    tls.write_all(&exit_buffer).unwrap();
    assert_eq!(ciphersuite.suite(), expected);
}

/// Test that the default provider returns the highest priority cipher suite
#[test]
fn test_default_client() {
    let (port, certificate) = start_server(server::Alg::PKCS_RSA_SHA512);
    let actual_suite = test_with_provider(default_provider(), port, vec![certificate]);
    assert_eq!(actual_suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
}

static RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
];

/// Generate a key pair, and sign/verify using each signature scheme.
#[rstest::rstest]
#[case::rsa_pkcs1_sha256(&rcgen::PKCS_RSA_SHA256, RSA_SCHEMES)]
#[case::ecdsa_p256(&rcgen::PKCS_ECDSA_P256_SHA256, &[SignatureScheme::ECDSA_NISTP256_SHA256])]
#[case::ecdsa_p384(&rcgen::PKCS_ECDSA_P384_SHA384, &[SignatureScheme::ECDSA_NISTP384_SHA384])]
#[case::ecdsa_p521(&rcgen::PKCS_ECDSA_P521_SHA512, &[SignatureScheme::ECDSA_NISTP521_SHA512])]
//#[case::ed25519_sign(&rcgen::PKCS_ED25519, &[SignatureScheme::ED25519])]
fn test_sign_and_verify(
    #[case] alg: &'static rcgen::SignatureAlgorithm,
    #[case] schemes: &[SignatureScheme],
) {
    let ours = rustls_cng_crypto::default_provider();
    let theirs = rustls::crypto::aws_lc_rs::default_provider();
    let pair = rcgen::KeyPair::generate_for(alg).unwrap();
    let rustls_private_key =
        PrivateKeyDer::from_pem_slice(pair.serialize_pem().as_bytes()).unwrap();

    let cert = CertificateParams::new(vec![])
        .unwrap()
        .self_signed(&pair)
        .unwrap();
    let cert = EndEntityCert::try_from(cert.der()).unwrap();

    let our_signing_key = ours
        .key_provider
        .load_private_key(rustls_private_key.clone_key())
        .unwrap();
    let their_signing_key = theirs
        .key_provider
        .load_private_key(rustls_private_key)
        .unwrap();

    for scheme in schemes {
        sign_and_verify(our_signing_key.as_ref(), &theirs, *scheme, &cert);
        sign_and_verify(their_signing_key.as_ref(), &ours, *scheme, &cert);
    }
}

fn sign_and_verify(
    signing_key: &dyn SigningKey,
    verifying_provider: &rustls::crypto::CryptoProvider,
    scheme: SignatureScheme,
    cert: &EndEntityCert<'_>,
) {
    let data = b"hello, world!";
    let signer = signing_key
        .choose_scheme(&[scheme])
        .expect("signing provider supports this scheme");
    let signature = signer.sign(data).unwrap();

    // verify
    let algs = verifying_provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(k, _v)| *k == scheme)
        .map(|(_k, v)| *v)
        .expect("verifying provider supports this scheme");
    assert!(!algs.is_empty());
    dbg!(algs);
    assert!(algs
        .iter()
        .any(|alg| { cert.verify_signature(*alg, data, &signature).is_ok() }));
}
