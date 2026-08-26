# DB Exploration Findings

## Overview

- **1957 services** across **570 hosts** and **1031 unique ports**
- **1163 unknown** services (59%), **372 SSH** (19%), **341 HTTP** (17%)
- **1395 services** have no product identified (71%)

---

## 1. Honeypot/Scanme Host: 31.13.224.245

**1004 open ports** — every port from 1 to 1024 is open. All show as `kind: unknown` with no banner or HTTP data. This is either a honeypot, a scanme host, or a misconfigured firewall passing all TCP SYN-ACKs. The only identified services are BGP (179) and RTSP (554).

---

## 2. ROSSSH — Romanian Government SSH

**11 instances** of `SSH-2.0-ROSSSH` on ports 22 and 2222. This is a custom SSH implementation used by Romanian government/ISP infrastructure. All found in the `78.159.150.x` range (Romanian IP space).

| IP | Port |
|----|------|
| 2.56.14.250 | 22 |
| 78.159.150.47-231 | 2222 (10 hosts) |

---

## 3. IPACCT ISP Infrastructure

Bulgarian ISP billing/management platform. 9 services across 3 IPs:

- **IPACCT Login** — billing portal (2.56.12.1, 78.142.30.1, 87.120.67.1)
- **IPBILL Login** — billing system (78.142.30.2)
- **IPACCT PON MANAGER** — fiber PON network management (78.142.30.1:8443)
- All running **freenginx/1.28.0** (the nginx fork after F5 acquisition)

---

## 4. MikroTik RouterOS Devices

**14 services** across 8 IPs:

- **Bandwidth-test servers** (port 2000) — 8 instances, including one labeled "EQUINIX SO1 CORE" (85.187.16.194)
- **RouterOS web interfaces** — 3 instances (45.149.234.1, 78.159.150.66, 87.120.67.24/107)
- **PPTP VPN** — 3 instances, one labeled "CentralenSklad" (78.159.150.79)

---

## 5. BGP Routers

**9 hosts** with BGP (port 179) open. These are core internet infrastructure:

2.56.12.1, 31.13.224.245, 45.149.240.0/26/226, 46.245.238.5, 78.159.150.23, 85.187.16.249, 87.120.67.1

---

## 6. Self-Hosted Applications

| App | IP | Port | Notes |
|-----|-----|------|-------|
| **Wazuh** (SIEM) | 2.56.14.119 | 443 | Security monitoring |
| **BigBlueButton** | 2.56.14.149, 205 | 443 | Video conferencing |
| **ERPNext** | — | — | ERP system (in signatures) |
| **Cacti** | 2.56.13.4 | 80, 443 | Network monitoring |
| **Nagios** | — | — | Monitoring (in signatures) |
| **osTicket** | 80.75.211.253 | 443 | "FlexyFans Helpdesk" |
| **Nextcloud** | 80.75.211.243, 45.149.235.187 | 80, 443 | File sync |
| **FreshRSS** | 45.149.235.75 | 8080 | RSS reader |
| **Miniflux** | 192.168.1.213 | 8080 | RSS reader (local) |
| **qBittorrent** | 192.168.1.111, 200 | 8080 | Torrent client (local) |
| **Crafty Controller** | 192.168.1.111, 203 | 8443 | Minecraft server manager (local) |
| **Reticulum** | 192.168.1.210 | 8080 | Mesh networking (local) |
| **Tactical RMM** | 2.56.14.140 | 443 | Remote monitoring/management |
| **Plesk Obsidian** | 45.149.234.251 | 443 | Hosting control panel |
| **XAMPP** | 80.75.211.100 | 80, 443 | Dev stack (also exposes MariaDB!) |
| **MDaemon Webmail** | 78.159.150.79 | 3000 | Email server |
| **Pritunl VPN** | 80.75.211.250 | 80, 443 | VPN server |
| **SoftEther VPN** | 45.149.234.180 | 443 | VPN server |
| **ScarletVPN** | 45.149.234.17 | 443 | VPN service |
| **Nginx Proxy Manager** | 78.159.150.21 | 80 | Reverse proxy |
| **Mistral Software** | 78.159.150.207 | 8082, 8087 | Custom software (IIS) |
| **AI Photo Editor** | 45.149.235.17 | 80, 443 | Web app |
| **Traffic Portal** | 45.149.234.216 | 443 | CDN/traffic management |
| **MyCDN** | 45.149.235.14 | 443 | Content delivery |
| **Pro C Bot** | 45.149.243.130 | 80 | Bot service |
| **Growth App** | 45.149.234.196 | 80, 443 | Web app |
| **Gifts Roll** | 45.149.234.238 | 443 | Web app |
| **Yeahgate** | 45.149.235.65 | 80, 443 | Gateway/proxy |
| **Rapas** | 2.56.14.194 | 80, 443 | Bulgarian app (Вход = Login) |
| **JAR Наклейки** | 45.149.234.138 | 80 | Sticker shop (Bulgarian) |
| **Юлия Bakery** | 45.149.234.63 | 80 | Recipe club (Russian) |
| **DevOps в тапках** | 45.149.234.23 | 80, 443 | Telegram channel (Russian) |
| **forum.kiru-love.ru** | 45.149.234.130 | 443 | Forum (Russian) |
| **games-xbox.ru** | 45.149.235.250 | 443 | Gaming site (Russian) |
| **SIGPLUS** | 45.149.240.217 | 80, 443 | ISP/telecom |
| **Visioniks** | 80.75.211.244 | 80, 443 | Video transcoding (WordPress) |
| **BMT Services** | 2.56.14.69-94 | 80, 443 | Server infrastructure (Server03-07) |
| **gandolf.ltmbg.com** | 2.56.14.124 | 80, 443 | Bulgarian site |
| **mail.vlahovski.com** | 2.56.14.166 | 80, 443 | Email server |
| **mail.technodes.pro** | 45.149.235.248 | 80, 443 | Email UI |
| **NL.LUNARLINK.NET** | 45.149.234.78 | 443 | Network link |
| **SURF.nl** | 45.149.234.123 | 443 | Dutch education/research ICT |
| **Web Admin** | 31.13.224.245 | 443 | Admin panel |

---

## 7. Network Equipment

| Type | IP | Port | Notes |
|------|-----|------|-------|
| **Ubiquiti** | 87.120.67.149 | 80, 443 | lighttpd/1.4.39 |
| **UniFi OS** | 78.142.30.146-150 | 443 | 5 controllers in same /24 |
| **TP-Link Router** | 78.159.150.73 | 80 | "Opening..." page |
| **MikroTik** | Multiple | 2000, 80, 443 | RouterOS + bandwidth-test |

---

## 8. Cameras (18 total)

- **10 Hikvision** — ports 88, 580, 581, 8080, 5555, 8085, 8001
- **3 Dahua** — ports 80, 85
- **2 IP Camera** — Boa (port 80), gSOAP (port 8084)
- **3 Hikvision IPCam** — port 8001 (no HTTP banner, detected via raw banner)
- **1 NETSurveillance** — 87.120.67.158:80 (no camera tags applied)
- **2 MOBOTIX** — 95.87.4.55:8012/8013 (not in DB, found manually)
- **Monitoring Display** — 31.13.227.186:80 (SN: 1001440001936, Dahua)

**0/18 have anonymous snapshot access.** MOBOTIX cameras do (not in DB).

---

## 9. Exposed Databases

- **MariaDB 10.4.32** — 80.75.211.100:3306 (exposed to internet, part of XAMPP stack)
- **PostgreSQL** — 192.168.1.208:5432 (local network only)

---

## 10. Interesting Server Headers

| Server | Count | Notes |
|--------|-------|-------|
| **freenginx/1.28.0** | 10 | nginx fork (IPACCT infrastructure) |
| **kittenx** | 2 | Unknown web server |
| **DNVRVS-Webs** | 4 | DVR web interface |
| **DVRDVS-Webs** | 2 | DVR web interface |
| **Webs** | 5 | Embedded web server |
| **GoAhead-Webs** | 1 | Embedded web server |
| **TornadoServer/6.5.4** | 1 | Python web server |
| **Werkzeug/3.1.8** | 1 | Python Flask |
| **kong/3.8.0** | 1 | API gateway |
| **QRATOR** | 1 | DDoS protection |
| **squid** | 1 | Proxy server |
| **Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.6.40** | 1 | Very old stack |

---

## 11. OpenSSH Version Distribution

| Version | Count | Notes |
|---------|-------|-------|
| OpenSSH 9.6p1 Ubuntu | 136 | Most common |
| OpenSSH 8.9p1 Ubuntu | 115 | |
| OpenSSH 8.2p1 Ubuntu | 21 | Older |
| OpenSSH 10.0p2 Debian | 10 | Newest |
| OpenSSH 7.6p1 Ubuntu | 5 | Very old |
| OpenSSH_for_Windows_8.6 | 1 | Windows |
| OpenSSH 9.7 FreeBSD | 1 | FreeBSD |
| ROSSSH | 11 | Custom (Romanian) |
| dropbear | 1 | Embedded (87.120.67.210) |

---

## 12. "Please wait, the page is opening..." Pages

**30+ instances** in the `87.120.67.x` range — all nginx/1.18.0. These are likely VPS/hosting provider splash pages or captive portals.

---

## 13. Unusual Services

- **MikroTik bandwidth-test** (port 2000) — 8 instances, some labeled with network names
- **PPTP VPN** (port 1723) — 3 instances including "CentralenSklad" and "EQUINIX SO1 CORE"
- **WSDAPI** (port 5357) — Windows Web Services API, 2 instances
- **SoftEther VPN** — 45.149.234.180:443
- **Reticulum Web UI** — 192.168.1.210:8080 (mesh networking, local)
- **dropbear SSH** — 87.120.67.210:22 (embedded SSH, likely router/IoT)

---

## 14. Russian-Language Services

Several Russian-language sites found in the `45.149.x.x` range:
- DevOps в тапках (Telegram channel)
- Юлия Bakery — закрытый клуб рецептов (recipe club)
- forum.kiru-love.ru (forum)
- games-xbox.ru (gaming)
- Яндекс (Yandex proxy)
- очередной vpn ("yet another vpn")
