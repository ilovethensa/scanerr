use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::models::{ServiceData, SshData, Protocol};

use super::engine::ProtocolProbe;

pub struct SshProbe;

impl ProtocolProbe for SshProbe {
    fn protocol(&self) -> Protocol { Protocol::Ssh }
    fn requires_probe_without_banner(&self) -> bool { true }
    fn detects_banner(&self, bytes: &[u8]) -> bool {
        String::from_utf8_lossy(bytes).starts_with("SSH-")
    }
    async fn probe(&self, ip: &str, port: u16, banner: &[u8], ua: &str) -> Result<ServiceData> {
        probe_ssh(ip, port, ua, banner).await
    }
}

/// Connect to an SSH server, do the version exchange + KEXINIT to extract
/// the host key and fingerprint. Returns enriched ServiceData.
/// `banner` is the pre-read banner bytes from the identifier.
pub async fn probe_ssh(ip: &str, port: u16, _user_agent: &str, banner: &[u8]) -> Result<ServiceData> {
    // Parse the banner we already have (may be empty if server waits for client)
    let server_version = String::from_utf8_lossy(banner).trim().to_string();
    let (product, version) = parse_ssh_version(&server_version);

    // Re-connect for the key exchange (we need a fresh stream after reading the banner)
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
    stream.set_nodelay(true)?;

    // Try to read server version — some servers send it immediately, others wait
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf)).await.unwrap_or(Ok(0))?;
    let mut server_version2 = String::from_utf8_lossy(&buf[..n]).trim().to_string();

    // Send our version
    let client_version = format!("SSH-2.0-scanerr_0.1\r\n");
    stream.write_all(client_version.as_bytes()).await?;

    // If server didn't send a version yet, read again after we sent ours
    if server_version2.is_empty() {
        let n2 = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf)).await.unwrap_or(Ok(0))?;
        server_version2 = String::from_utf8_lossy(&buf[..n2]).trim().to_string();
    }

    // Parse product/version from whichever version string we got
    let (product2, version2) = parse_ssh_version(&server_version2);
    let final_product = product2.or(product);
    let final_version = version2.or(version);
    let final_banner = if !server_version2.is_empty() { server_version2 } else { server_version };

    // If we got no SSH banner at all, this isn't SSH
    if final_banner.is_empty() || !final_banner.starts_with("SSH-") {
        anyhow::bail!("no SSH banner received");
    }

    // Send KEXINIT with reasonable algorithm lists
    let kexinit = build_kexinit();
    send_msg(&mut stream, &kexinit).await?;

    // Read server KEXINIT
    let _server_kexinit = read_ssh_msg(&mut stream).await.unwrap_or_default();

    // Send our DH init (g=2, random x, compute g^x mod p)
    // We use a minimal DH to trigger the server's KEXDH_REPLY which contains the host key
    let (dh_init, _priv_key_bytes) = build_kexdh_init()?;
    send_msg(&mut stream, &dh_init).await?;

    // Read server response — should contain KEXDH_REPLY with host key
    let host_key_info = loop {
        match read_ssh_msg(&mut stream).await {
            Ok(msg) if msg.len() > 0 && msg[0] == 31 => { // SSH_MSG_KEXDH_REPLY = 31
                break parse_host_key_from_reply(&msg);
            }
            Ok(_msg) => continue, // skip other messages
            Err(_) => break None,
        }
    };

    let mut data = ServiceData::default();
    data.kind = "ssh".into();
    data.product = final_product.clone();
    data.version = final_version.clone();
    data.banner = Some(final_banner.clone());

    data.ssh = Some(SshData {
        raw: final_banner,
        key_type: host_key_info.as_ref().and_then(|k| k.0.clone()),
        key: host_key_info.as_ref().and_then(|k| k.1.clone()),
        fingerprint: host_key_info.as_ref().and_then(|k| k.2.clone()),
        product: final_product,
        version: final_version,
    });

    Ok(data)
}

fn parse_ssh_version(version: &str) -> (Option<String>, Option<String>) {
    // Format: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1
    let rest = version.strip_prefix("SSH-2.0-").unwrap_or(version);
    // Split on first space to separate "OpenSSH_9.2p1" from "Debian-2+deb12u1"
    let parts: Vec<&str> = rest.splitn(2, ' ').collect();
    let product_version = parts[0];

    // Split product from version: "OpenSSH_9.2p1" -> ("OpenSSH", "9.2p1")
    let (prod, ver) = if let Some(pos) = product_version.find('_') {
        (product_version[..pos].to_string(), Some(product_version[pos + 1..].to_string()))
    } else {
        (product_version.to_string(), None)
    };

    // Strip to printable ASCII — prevents binary banner leaks
    let clean_prod: String = prod.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect();
    let clean_ver = ver.map(|v| v.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect::<String>());

    let clean_prod = if clean_prod.is_empty() { None } else { Some(clean_prod) };
    let clean_ver = clean_ver.and_then(|v| if v.is_empty() { None } else { Some(v) });

    (clean_prod, clean_ver)
}

fn build_kexinit() -> Vec<u8> {

    // SSH_MSG_KEXINIT (20) with random cookie (16 bytes)
    let mut payload = Vec::new();
    payload.push(20); // SSH_MSG_KEXINIT
    payload.extend_from_slice(&[0u8; 16]); // cookie

    // Name lists with common algorithms
    let kex_algos = "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1";
    let host_key_algos = "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256";
    let enc_c2s = "aes256-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com";
    let enc_s2c = "aes256-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com";
    let mac_c2s = "hmac-sha2-256,hmac-sha2-512,hmac-sha1";
    let mac_s2c = "hmac-sha2-256,hmac-sha2-512,hmac-sha1";
    let comp_c2s = "none";
    let comp_s2c = "none";
    let lang_c2s = "";
    let lang_s2c = "";

    for name_list in [kex_algos, host_key_algos, enc_c2s, enc_s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c, lang_c2s, lang_s2c] {
        let len = name_list.len() as u32;
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(name_list.as_bytes());
    }

    payload.push(0); // first_kex_packet_follows
    payload.extend_from_slice(&[0, 0, 0, 0]); // reserved

    wrap_ssh_msg(&payload)
}

fn build_kexdh_init() -> Result<(Vec<u8>, Vec<u8>)> {
    // SSH_MSG_KEXDH_INIT (30)
    // Generate a simple private key (just for triggering the server reply)
    let mut msg = Vec::new();
    msg.push(30); // SSH_MSG_KEXDH_INIT
    // Public value: a small value for g=2 (we just need the server to respond with its host key)
    let e: [u8; 32] = [0x02; 32]; // 2^8 or similar small value
    msg.extend_from_slice(&e);

    Ok((wrap_ssh_msg(&msg), e.to_vec()))
}

fn wrap_ssh_msg(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn send_msg(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream.write_all(data).await?;
    Ok(())
}

async fn read_ssh_msg(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut len_buf)).await??;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 35000 {
        anyhow::bail!("SSH message too large: {}", len);
    }
    let mut payload = vec![0u8; len];
    tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut payload)).await??;
    Ok(payload)
}

/// Parse the host key from SSH_MSG_KEXDH_REPLY.
/// Format: byte SSH_MSG_KEXDH_REPLY, mpint f, string host_key_type, string host_key, string signature, string hash
/// Returns (key_type, base64_key, fingerprint)
fn parse_host_key_from_reply(msg: &[u8]) -> Option<(Option<String>, Option<String>, Option<String>)> {
    if msg.len() < 5 || msg[0] != 31 {
        return None;
    }

    let mut pos = 1;

    // Skip the DH public value (mpint f) — read length and skip
    if pos + 4 > msg.len() { return None; }
    let f_len = u32::from_be_bytes([msg[pos], msg[pos+1], msg[pos+2], msg[pos+3]]) as usize;
    pos += 4 + f_len;

    // Read host key type (string)
    if pos + 4 > msg.len() { return None; }
    let kt_len = u32::from_be_bytes([msg[pos], msg[pos+1], msg[pos+2], msg[pos+3]]) as usize;
    pos += 4;
    if pos + kt_len > msg.len() { return None; }
    let key_type = String::from_utf8_lossy(&msg[pos..pos + kt_len]).to_string();
    pos += kt_len;

    // Read host key (string)
    if pos + 4 > msg.len() { return None; }
    let hk_len = u32::from_be_bytes([msg[pos], msg[pos+1], msg[pos+2], msg[pos+3]]) as usize;
    pos += 4;
    if pos + hk_len > msg.len() { return None; }
    let host_key = &msg[pos..pos + hk_len];

    // Base64 encode the key
    use base64::Engine;
    let b64_key = base64::engine::general_purpose::STANDARD.encode(host_key);

    // Compute SHA256 fingerprint (Shodan format: "SHA256:<base64>")
    let mut hasher = Sha256::new();
    hasher.update(host_key);
    let hash = hasher.finalize();
    let fp = format!("SHA256:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash));

    Some((Some(key_type), Some(b64_key), Some(fp)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_version() {
        let (product, version) = parse_ssh_version("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1");
        assert_eq!(product.as_deref(), Some("OpenSSH"));
        assert_eq!(version.as_deref(), Some("9.2p1"));

        let (product, version) = parse_ssh_version("SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4");
        assert_eq!(product.as_deref(), Some("OpenSSH"));
        assert_eq!(version.as_deref(), Some("10.0p2"));
    }

    #[tokio::test]
    async fn test_probe_ssh() {
        let data = probe_ssh("192.168.1.111", 22, "scanerr", b"SSH-2.0-OpenSSH_9.2p1\r\n").await.unwrap();
        assert_eq!(data.kind, "ssh");
        assert_eq!(data.product.as_deref(), Some("OpenSSH"));
        assert!(data.ssh.is_some());
    }
}
