//! Util for creating test servers, adapted from <https://github.com/rustls/rustls/blob/20de56876d8bc45224c351339337c61126c1c954/provider-example/examples/server.rs#L58>
use std::io::Write;
use std::sync::Arc;

use rcgen::{Issuer, SignatureAlgorithm};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::Acceptor;
use rustls::ServerConfig;

/// Algorithm to use for the server keypair. Required to workaround
/// `rcgen::SignatureAlgorithm` not being `PartialEq`
#[allow(non_camel_case_types)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Alg {
    PKCS_ED25519,
    PKCS_RSA_SHA512,
    PKCS_RSA_SHA384,
    PKCS_ECDSA_P256_SHA256,
}

/// Start a server that uses [`rustls_cng_crypto::default_provider`] on a random port,
/// generating a certificate for `localhost` with the specified algorithm.
///
/// The server will handle a single connection.
///
/// Returns the port the server is listening on and the CA certificate used to sign the server certificate.
#[must_use]
pub fn start_server(alg: &'static rcgen::SignatureAlgorithm) -> (u16, CertificateDer<'static>) {
    let pki = TestPki::for_algorithm(alg);
    let ca_cert = pki.ca_cert.clone();
    let server_config = pki.server_config();

    let listener = std::net::TcpListener::bind("[::]:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut stream = listener.incoming().next().unwrap().unwrap();
        let mut acceptor = Acceptor::default();

        loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                let mut conn = accepted.into_connection(server_config.clone()).unwrap();
                let msg = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: Closed\r\n",
                    "Content-Type: text/html\r\n",
                    "\r\n",
                    "<h1>Hello World!</h1>\r\n"
                )
                .as_bytes();

                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();
            }
        }
    });
    (port, ca_cert)
}

struct TestPki {
    ca_cert: CertificateDer<'static>,
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
}

impl TestPki {
    fn for_algorithm(alg: &'static SignatureAlgorithm) -> Self {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "rustls-cng-crypto tests");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];

        let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let server_cert = server_ee_params.signed_by(&server_key, &issuer).unwrap();

        Self {
            ca_cert: ca_cert.into(),
            server_cert_der: server_cert.into(),
            server_key_der: PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        }
    }

    fn server_config(self) -> Arc<ServerConfig> {
        let mut server_config =
            ServerConfig::builder_with_provider(rustls_cng_crypto::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![self.server_cert_der], self.server_key_der)
                .unwrap();

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }
}
