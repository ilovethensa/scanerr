use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::models::{Protocol, ServiceData};
use reqwest::Client;

use crate::{bgp, ftp, imap, mikrotik, mqtt, mysql, pop3, pptp, rtsp, sccp, smtp, ssh, telnet};

/// Trait implemented by each protocol detector.
pub trait ProtocolProbe {
    fn protocol(&self) -> Protocol;

    fn requires_probe_without_banner(&self) -> bool { false }

    fn detects_banner(&self, _bytes: &[u8]) -> bool { false }

    fn probe(
        &self,
        ip: &str,
        port: u16,
        banner: &[u8],
        user_agent: &str,
    ) -> impl std::future::Future<Output = Result<ServiceData>> + Send;
}

// ─── Enum dispatcher (avoids dyn) ────────────────────────────────────────────

macro_rules! probe_kinds {
    ($($variant:ident($path:path)),+ $(,)?) => {
        pub enum ProbeKind {
            $($variant($path)),+
        }

        impl ProtocolProbe for ProbeKind {
            fn protocol(&self) -> Protocol {
                match self { $(Self::$variant(p) => ProtocolProbe::protocol(p)),+ }
            }

            fn requires_probe_without_banner(&self) -> bool {
                match self { $(Self::$variant(p) => ProtocolProbe::requires_probe_without_banner(p)),+ }
            }

            fn detects_banner(&self, bytes: &[u8]) -> bool {
                match self { $(Self::$variant(p) => ProtocolProbe::detects_banner(p, bytes)),+ }
            }

            async fn probe(&self, ip: &str, port: u16, banner: &[u8], user_agent: &str) -> Result<ServiceData> {
                match self {
                    $(Self::$variant(p) => {
                        let mut d = ProtocolProbe::probe(p, ip, port, banner, user_agent).await?;
                        d.kind = self.protocol().as_str().into();
                        Ok(d)
                    }),+
                }
            }
        }

        impl ProbeRegistry {
            pub fn new() -> Self {
                Self {
                    probes: vec![ $(ProbeKind::$variant($path)),+ ],
                }
            }
        }
    };
}

probe_kinds! {
    Ssh(ssh::SshProbe),
    Ftp(ftp::FtpProbe),
    Smtp(smtp::SmtpProbe),
    Imap(imap::ImapProbe),
    Pop3(pop3::Pop3Probe),
    Telnet(telnet::TelnetProbe),
    Mysql(mysql::MysqlProbe),
    Pptp(pptp::PptpProbe),
    Mqtt(mqtt::MqttProbe),
    Sccp(sccp::SccpProbe),
    Mikrotik(mikrotik::MikrotikProbe),
    Rtsp(rtsp::RtspProbe),
    Bgp(bgp::BgpProbe),
}

// ─── Registry ─────────────────────────────────────────────────────────────────

pub struct ProbeRegistry {
    probes: Vec<ProbeKind>,
}

impl ProbeRegistry {
    /// Run the banner-first dispatcher.
    pub async fn dispatch(
        &self,
        ip: &str,
        port: u16,
        user_agent: &str,
        client: &Client,
    ) -> Result<ServiceData> {
        let is_https_port = port == 443 || port == 8443;

        let banner = if is_https_port {
            Vec::new()
        } else {
            match read_banner(ip, port).await {
                Ok(b) => b,
                Err(_) => {
                    let mut data = ServiceData::default();
                    data.kind = "firewalled".into();
                    return Ok(data);
                }
            }
        };

        if !banner.is_empty() {
            let mut best: Option<(&ProbeKind, u32)> = None;
            for p in &self.probes {
                if !p.requires_probe_without_banner() && p.detects_banner(&banner) {
                    let prio = probe_priority(p.protocol());
                    if best.is_none() || prio > best.as_ref().unwrap().1 {
                        best = Some((p, prio));
                    }
                }
            }
            if let Some((probe, _)) = best {
                return probe.probe(ip, port, &banner, user_agent).await;
            }
        }

        if let Ok(data) = try_http_fallback(ip, port, client).await {
            if data.product.is_some() || data.http.is_some() {
                return Ok(data);
            }
        }

        for p in &self.probes {
            if p.requires_probe_without_banner() {
                if let Ok(data) = p.probe(ip, port, &banner, user_agent).await {
                    return Ok(data);
                }
            }
        }

        Ok(ServiceData::default())
    }
}

fn probe_priority(proto: Protocol) -> u32 {
    match proto {
        Protocol::Ssh   => 100,
        Protocol::Ftp   => 90,
        Protocol::Smtp  => 90,
        Protocol::Imap  => 80,
        Protocol::Pop3  => 80,
        Protocol::Telnet => 80,
        Protocol::Mysql => 80,
        Protocol::Pptp  => 60,
        Protocol::Mqtt  => 60,
        Protocol::Sccp  => 60,
        Protocol::Mikrotik => 70,
        Protocol::Rtsp    => 70,
        Protocol::Bgp     => 50,
        _ => 0,
    }
}

async fn read_banner(ip: &str, port: u16) -> Result<Vec<u8>> {
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        TcpStream::connect(format!("{}:{}", ip, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout"))?
    .map_err(|e| anyhow::anyhow!("connect failed: {}", e))?;

    let mut stream = stream;
    stream.set_nodelay(true)?;

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))?;

    Ok(buf[..n].to_vec())
}

async fn try_http_fallback(
    ip: &str,
    port: u16,
    client: &Client,
) -> Result<ServiceData> {
    let is_https_port = port == 443 || port == 8443;
    let (first, second) = if is_https_port {
        ("https", "http")
    } else {
        ("http", "https")
    };

    if let Ok(data) = crate::http::probe(first, ip, port, client).await {
        return Ok(data);
    }
    if let Ok(data) = crate::http::probe(second, ip, port, client).await {
        return Ok(data);
    }

    if let Ok(Ok((_, ssl_data))) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::tls::connect(ip, port),
    ).await {
        let mut data = ServiceData::default();
        data.kind = "tls".into();
        if ssl_data.subject_cn.is_some() || ssl_data.issuer_cn.is_some() {
            data.ssl = Some(ssl_data);
        }
        return Ok(data);
    }

    Ok(ServiceData::default())
}
