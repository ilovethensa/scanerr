use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use x509_parser::prelude::*;

use crate::models::SslData;

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub async fn tls_connect(
    ip: &str,
    port: u16,
) -> Result<(TlsStream<TcpStream>, SslData)> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect(format!("{}:{}", ip, port)).await?;

    let domain = rustls::pki_types::ServerName::try_from(ip.to_string())?;

    let tls_stream = connector.connect(domain, tcp).await?;

    let peer_cert = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first().cloned());

    let ssl_data = extract_ssl_data(peer_cert.as_ref());

    Ok((tls_stream, ssl_data))
}

fn extract_ssl_data(cert: Option<&rustls::pki_types::CertificateDer<'static>>) -> SslData {
    match cert {
        Some(cert) => {
            let (_, parsed) = match X509Certificate::from_der(cert.as_ref()) {
                Ok(v) => v,
                Err(_) => {
                    return SslData {
                        subject_cn: None,
                        issuer_cn: None,
                        self_signed: false,
                    }
                }
            };

            // 2.5.4.3=CN, 2.5.4.10=O
            let subject_cn = find_dn_attr(&parsed.subject(), "2.5.4.3")
                .or_else(|| find_dn_attr(&parsed.subject(), "2.5.4.10"));

            let issuer_cn = find_dn_attr(&parsed.issuer(), "2.5.4.3")
                .or_else(|| find_dn_attr(&parsed.issuer(), "2.5.4.10"));

            let self_signed = parsed.subject().to_string() == parsed.issuer().to_string();

            SslData {
                subject_cn,
                issuer_cn,
                self_signed,
            }
        }
        None => SslData {
            subject_cn: None,
            issuer_cn: None,
            self_signed: false,
        },
    }
}

fn find_dn_attr(name: &X509Name, target_oid: &str) -> Option<String> {
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid_str = attr.attr_type().to_string();
            if oid_str == target_oid {
                // attr_value() returns raw ASN.1; decode the UTF-8 bytes directly
                let raw = attr.attr_value().data;
                if let Ok(val) = std::str::from_utf8(raw) {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ssl_data_no_cert() {
        let data = extract_ssl_data(None);
        assert!(!data.self_signed);
        assert!(data.subject_cn.is_none());
        assert!(data.issuer_cn.is_none());
    }
}
