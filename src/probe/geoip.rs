use anyhow::Result;

pub struct GeoIpInfo {
    pub country_code: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

pub fn lookup(ip: &str, db_path: &str) -> Result<GeoIpInfo> {
    let reader = maxminddb::Reader::open_readfile(db_path)?;

    let city: maxminddb::geoip2::City = reader.lookup(ip.parse()?)?;

    let country_code = city
        .country
        .as_ref()
        .and_then(|c| c.iso_code.map(|s| s.to_string()));

    Ok(GeoIpInfo {
        country_code,
        asn: None,
        org: None,
    })
}

pub fn lookup_asn(ip: &str, db_path: &str) -> Result<GeoIpInfo> {
    let reader = maxminddb::Reader::open_readfile(db_path)?;

    let asn: maxminddb::geoip2::Asn = reader.lookup(ip.parse()?)?;

    Ok(GeoIpInfo {
        country_code: None,
        asn: asn.autonomous_system_number.map(|n| n as u32),
        org: asn.autonomous_system_organization.map(|s| s.to_string()),
    })
}
