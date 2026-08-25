use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use crate::models::SslData;

pub async fn tls_connect(
    ip: &str,
    port: u16,
) -> Result<(TlsStream<TcpStream>, SslData)> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
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
            let subject = extract_cn_from_cert(cert);
            let issuer = extract_issuer_from_cert(cert);
            let self_signed = subject == issuer;

            SslData {
                subject_cn: subject,
                issuer_cn: issuer,
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

fn extract_cn_from_cert(_cert: &rustls::pki_types::CertificateDer<'static>) -> Option<String> {
    // Parse the certificate to extract CN
    // For now, return None as a placeholder
    None
}

fn extract_issuer_from_cert(_cert: &rustls::pki_types::CertificateDer<'static>) -> Option<String> {
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
