use anyhow::Result;
use maxminddb::Reader;

pub struct GeoIpInfo {
    pub country_code: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

/// Holds the MaxMind databases open for the lifetime of the process.
/// Open once at startup via [`GeoIp::open`] and reuse across all lookups —
/// the underlying mmap is shared, so this avoids re-reading the file on every
/// probed IP.
pub struct GeoIp {
    city: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

impl GeoIp {
    /// Open the City and ASN databases once. A `None` path, or a file that
    /// fails to open, simply leaves that lookup disabled rather than failing
    /// the whole probe stage (matching the previous per-call behaviour).
    pub fn open(geoip_db: Option<&str>, asn_db: Option<&str>) -> GeoIp {
        let city = match geoip_db {
            Some(p) => match Reader::open_readfile(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!("GeoIP: failed to open city DB '{}': {}", p, e);
                    None
                }
            },
            None => None,
        };
        let asn = match asn_db {
            Some(p) => match Reader::open_readfile(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!("GeoIP: failed to open ASN DB '{}': {}", p, e);
                    None
                }
            },
            None => None,
        };
        GeoIp { city, asn }
    }

    pub fn lookup(&self, ip: &str) -> Result<GeoIpInfo> {
        let reader = self
            .city
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("city DB not loaded"))?;

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

    pub fn lookup_asn(&self, ip: &str) -> Result<GeoIpInfo> {
        let reader = self
            .asn
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("asn DB not loaded"))?;

        let asn: maxminddb::geoip2::Asn = reader.lookup(ip.parse()?)?;

        Ok(GeoIpInfo {
            country_code: None,
            asn: asn.autonomous_system_number.map(|n| n as u32),
            org: asn.autonomous_system_organization.map(|s| s.to_string()),
        })
    }
}
