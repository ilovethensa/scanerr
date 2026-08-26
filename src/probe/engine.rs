use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::models::{Protocol, ServiceData};

use super::{bgp, ftp, hikvision, imap, mikrotik, mqtt, mysql, pop3, pptp, rtsp, sccp, smtp, ssh, telnet};

/// Trait implemented by each protocol detector.
pub trait ProtocolProbe {
    /// Protocol identity.
    fn protocol(&self) -> Protocol;

    /// `true` when the service never sends an initial banner and must be
    /// actively probed (PPTP, MQTT).
    fn requires_probe_without_banner(&self) -> bool { false }

    /// Passive banner detection — does this protocol recognize the bytes
    /// in `banner`?  Runs on **any** port, independently of the port number.
    fn detects_banner(&self, _bytes: &[u8]) -> bool { false }

    /// Execute the protocol probe.  `banner` contains the passive bytes
    /// already read (may be empty).
    fn probe(
        &self,
        ip: &str,
        port: u16,
        banner: &[u8],
        user_agent: &str,
    ) -> impl std::future::Future<Output = Result<ServiceData>> + Send;
}

// ─── Enum dispatcher (avoids dyn) ────────────────────────────────────────────

pub enum ProbeKind {
    Ftp(ftp::FtpProbe),
    Ssh(ssh::SshProbe),
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
    Hikvision(hikvision::HikvisionProbe),
}

impl ProtocolProbe for ProbeKind {
    fn protocol(&self) -> Protocol {
        match self {
            Self::Ftp(p) => p.protocol(),
            Self::Ssh(p) => p.protocol(),
            Self::Smtp(p) => p.protocol(),
            Self::Imap(p) => p.protocol(),
            Self::Pop3(p) => p.protocol(),
            Self::Telnet(p) => p.protocol(),
            Self::Mysql(p) => p.protocol(),
            Self::Pptp(p) => p.protocol(),
            Self::Mqtt(p) => p.protocol(),
            Self::Sccp(p) => p.protocol(),
            Self::Mikrotik(p) => p.protocol(),
            Self::Rtsp(p) => p.protocol(),
            Self::Bgp(p) => p.protocol(),
            Self::Hikvision(p) => p.protocol(),
        }
    }

    fn requires_probe_without_banner(&self) -> bool {
        match self {
            Self::Ftp(p) => p.requires_probe_without_banner(),
            Self::Ssh(p) => p.requires_probe_without_banner(),
            Self::Smtp(p) => p.requires_probe_without_banner(),
            Self::Imap(p) => p.requires_probe_without_banner(),
            Self::Pop3(p) => p.requires_probe_without_banner(),
            Self::Telnet(p) => p.requires_probe_without_banner(),
            Self::Mysql(p) => p.requires_probe_without_banner(),
            Self::Pptp(p) => p.requires_probe_without_banner(),
            Self::Mqtt(p) => p.requires_probe_without_banner(),
            Self::Sccp(p) => p.requires_probe_without_banner(),
            Self::Mikrotik(p) => p.requires_probe_without_banner(),
            Self::Rtsp(p) => p.requires_probe_without_banner(),
            Self::Bgp(p) => p.requires_probe_without_banner(),
            Self::Hikvision(p) => p.requires_probe_without_banner(),
        }
    }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        match self {
            Self::Ftp(p) => p.detects_banner(bytes),
            Self::Ssh(p) => p.detects_banner(bytes),
            Self::Smtp(p) => p.detects_banner(bytes),
            Self::Imap(p) => p.detects_banner(bytes),
            Self::Pop3(p) => p.detects_banner(bytes),
            Self::Telnet(p) => p.detects_banner(bytes),
            Self::Mysql(p) => p.detects_banner(bytes),
            Self::Pptp(p) => p.detects_banner(bytes),
            Self::Mqtt(p) => p.detects_banner(bytes),
            Self::Sccp(p) => p.detects_banner(bytes),
            Self::Mikrotik(p) => p.detects_banner(bytes),
            Self::Rtsp(p) => p.detects_banner(bytes),
            Self::Bgp(p) => p.detects_banner(bytes),
            Self::Hikvision(p) => p.detects_banner(bytes),
        }
    }

    async fn probe(&self, ip: &str, port: u16, banner: &[u8], user_agent: &str) -> Result<ServiceData> {
        match self {
            Self::Ftp(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Ssh(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Smtp(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Imap(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Pop3(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Telnet(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Mysql(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Pptp(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Mqtt(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Sccp(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Mikrotik(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Rtsp(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Bgp(p) => p.probe(ip, port, banner, user_agent).await,
            Self::Hikvision(p) => p.probe(ip, port, banner, user_agent).await,
        }
    }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

pub struct ProbeRegistry {
    probes: Vec<ProbeKind>,
}

impl ProbeRegistry {
    pub fn new() -> Self {
        Self {
            probes: vec![
                ProbeKind::Ssh(ssh::SshProbe),
                ProbeKind::Ftp(ftp::FtpProbe),
                ProbeKind::Smtp(smtp::SmtpProbe),
                ProbeKind::Imap(imap::ImapProbe),
                ProbeKind::Pop3(pop3::Pop3Probe),
                ProbeKind::Telnet(telnet::TelnetProbe),
                ProbeKind::Mysql(mysql::MysqlProbe),
                ProbeKind::Pptp(pptp::PptpProbe),
                ProbeKind::Mqtt(mqtt::MqttProbe),
                ProbeKind::Sccp(sccp::SccpProbe),
                ProbeKind::Mikrotik(mikrotik::MikrotikProbe),
                ProbeKind::Rtsp(rtsp::RtspProbe),
                ProbeKind::Bgp(bgp::BgpProbe),
                ProbeKind::Hikvision(hikvision::HikvisionProbe),
            ],
        }
    }

    /// Run the banner-first dispatcher.
    pub async fn dispatch(
        &self,
        ip: &str,
        port: u16,
        user_agent: &str,
    ) -> Result<ServiceData> {
        // 1. Connect and read banner
        let connect_result = read_banner(ip, port).await;
        let banner = match connect_result {
            Ok(b) => b,
            Err(_) => {
                // Connection refused or timed out — port is firewalled
                let mut data = ServiceData::default();
                data.kind = "firewalled".into();
                return Ok(data);
            }
        };

        // 2. Run every probe's `detects_banner` over the captured bytes
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

        // 3. Banner empty or unrecognized → try HTTP/TLS fallback
        if let Ok(data) = try_http_fallback(ip, port, user_agent).await {
            if data.product.is_some() || data.http.is_some() {
                return Ok(data);
            }
        }

        // 4. Last resort: run active-only probes (PPTP, MQTT, etc.)
        for p in &self.probes {
            if p.requires_probe_without_banner() {
                if let Ok(data) = p.probe(ip, port, &banner, user_agent).await {
                    return Ok(data);
                }
            }
        }

        // 5. Nothing matched
        Ok(ServiceData::default())
    }
}

/// Higher = tried first when multiple probes match a banner.
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
        Protocol::Hikvision => 65,
        _ => 0,
    }
}

async fn read_banner(ip: &str, port: u16) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
    stream.set_nodelay(true)?;

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))?;

    Ok(buf[..n].to_vec())
}

async fn try_http_fallback(
    ip: &str,
    port: u16,
    user_agent: &str,
) -> Result<ServiceData> {
    // Try plain HTTP first
    if let Ok(data) = super::http::probe_http("http", ip, port, user_agent).await {
        return Ok(data);
    }
    // Then HTTPS
    if let Ok(data) = super::http::probe_http("https", ip, port, user_agent).await {
        return Ok(data);
    }
    // Then raw TLS (cert data only)
    if let Ok((_, ssl_data)) = super::tls::tls_connect(ip, port).await {
        let mut data = ServiceData::default();
        data.kind = "tls".into();
        if ssl_data.subject_cn.is_some() || ssl_data.issuer_cn.is_some() {
            data.ssl = Some(ssl_data);
        }
        return Ok(data);
    }

    Ok(ServiceData::default())
}
