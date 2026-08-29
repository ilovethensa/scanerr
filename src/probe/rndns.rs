use anyhow::Result;

pub async fn resolve(ip: &str) -> Result<Option<String>> {
    let addr: std::net::IpAddr = ip.parse()?;
    let mut addrs = tokio::net::lookup_host(format!("{}:0", addr)).await?;
    let entry = addrs.next().ok_or_else(|| anyhow::anyhow!("no rDNS result"))?;
    let hostname = entry.ip().to_string();
    if hostname != ip {
        Ok(Some(hostname))
    } else {
        Ok(None)
    }
}
