# Camera Research Notes

## Camera Types Found in Database

### Hikvision
- Web ports: 80, 88, 580, 581, 8080, 8085, 5555
- RTSP port: 554
- RTSP path: `rtsp://ip:554/Streaming/Channels/101`
- ISAPI snapshot: `http://ip/ISAPI/Streaming/channels/101/picture` (401 auth required)
- Uses 302 redirect from HTTP:80 → HTTPS:443
- HTTPS serves meta refresh → `/webpages/index.html` (TP-Link AX80v1 firmware)
- Product detection works via fingerprint signatures on web UI

### Dahua / NETSurveillance
- Web ports: 80, 85
- RTSP port: 554
- RTSP path: `rtsp://ip:554/cam/realmonitor?channel=1&subtype=0`
- Server header: `uc-httpd 1.0.0`
- Login page: `/Login.htm` (MD5 challenge-response auth)
- `snap.jpg` returns static 36x25 placeholder (identical across all cameras)
- No anonymous snapshot access

### IP Camera (gSOAP)
- Port: 8084
- Minimal web interface, gSOAP/2.8 server header

## Authentication

All cameras require authentication for:
- RTSP stream access (401 Unauthorized)
- ISAPI snapshot endpoints (401 Unauthorized)
- HTTP CGI endpoints (varies)

### Default Credentials to Try
1. `admin:` (blank password) — common on NETSurveillance
2. `admin:admin`
3. `admin:12345`
4. `admin:123456`
5. `admin:888888`

### NETSurveillance MD5 Auth Flow
1. GET `/Login.htm` → extract `md5_key` from JS
2. If `md5_key == "0"`: POST plain `username` + `password`
3. If `md5_key != "0"`: MD5 challenge-response:
   - `temp = convert_crypt(hex_md5(password))`
   - `temp1 = convert_crypt(hex_md5(temp + md5_key))`
   - POST `param1` (username) + `param2` (temp1[:5])
4. 2-second busy wait required before submit

## Snapshot Endpoints (All Require Auth)

| Camera Type | Endpoint | Method |
|-------------|----------|--------|
| Hikvision | `/ISAPI/Streaming/channels/101/picture` | GET |
| Dahua | `/cgi-bin/snapshot.cgi?channel=1` | GET |
| Dahua | `/tmpfs/snap.jpg` | GET |
| Generic | `/snap.jpg` | GET (placeholder only) |

## RTSP Stream Paths

| Camera Type | Path |
|-------------|------|
| Hikvision | `/Streaming/Channels/101` |
| Dahua | `/cam/realmonitor?channel=1&subtype=0` |
| Dahua alt | `/h264/ch1/main/av_stream` |
| Generic | `/` or `/live` or `/1` |

## Known Camera IPs

### Cam-Webs
- Server header: `Cam-Webs`
- Web port: 9090
- Redirects `/` → `/browse/index.asp`
- Auth: HTTP Basic, realm `Megapixel_IP_Camera`
- Snapshot: `/browse/snapshot.asp` (401 auth required)
- No anonymous access
- Default creds unknown (admin:blank, admin:admin, etc. all fail)

### MOBOTIX (Anonymous Access!)
- Manufacturer: MOBOTIX AG, Germany
- Snapshot: `http://ip:port/record/current.jpg` (no auth!)
- Web interface: `/control/userimage.html` (302 redirect from `/`)
- Comment in JPEG: `#:M1IMG`, `MXF`
- Server: `thttpd/2.19-MX` (some units)
- Port varies: 8012, 8013, 4433, 4436, etc.
- Resolutions: 1280x960, 2048x1536 (multi-lens models return 4-way split)
- Multi-lens models (M15/M16): single JPEG contains 4 camera views tiled in a 2x2 grid
- Some models return `501 Not Implemented` on `/` but still serve `/record/current.jpg`
- No authentication required for snapshot or web interface

### Boa/ACTi-style (Anonymous Access!)
- Server header: `Boa/0.94.14rc21`
- Snapshot: `http://ip:port/cgi-bin/viewer/video.jpg` (no auth!)
- CGI info: `http://ip:port/cgi-bin/viewer/getparam.cgi?system_hostname&videoin&network`
- Web interface: `/` (26KB HTML page with jQuery)
- Response: 1600x1200 JPEG, ~93KB, no authentication required
- Some units require HTTP Basic Auth (realm `streaming_server`)

### Boa/ACTi-style (Mixed Auth!)
- Server header: `Boa/0.94.14rc21`
- Main page requires HTTP Basic Auth (realm `streaming_server`)
- Snapshot accessible without auth: `http://ip:port/cgi-bin/viewer/video.jpg`
- CGI info requires auth: `/cgi-bin/viewer/getparam_cache.cgi`
- Response: 1280x800+ JPEG, ~94KB, snapshot works without authentication
- Default creds unknown (admin:blank, admin:admin, etc. all fail)
- Same Boa server used by Vivotek and ACTi cameras

### Axis Cameras (Anonymous Access!)
- Snapshot: `http://ip:port/axis-cgi/jpg/image.cgi` (no auth!)
- Higher res: `http://ip:port/axis-cgi/jpg/image.cgi?resolution=1920x1080`
- MJPEG stream: `http://ip:port/mjpg/video.mjpg` (multipart/x-mixed-replace)
- Web interface: `http://ip:port/view/viewer_index.shtml`
- Model examples: AXIS M1025 Network Camera
- Port varies: 80, 8080, 7443, etc.
- Response: 1920x1080 JPEG, ~250KB, no authentication required

### NETSurveillance / Dahua-like
- Login: `/Login.htm` (MD5 challenge-response auth)
- `snap.jpg` = static 36x25 placeholder (identical across all cameras)
- No anonymous snapshot access
- Also found on non-standard port 8001 (151.251.160.69)
- `config.js` and `m.jsp` (obfuscated JS) available without auth

### Hikvision
- ISAPI snapshot: `http://ip/ISAPI/Streaming/channels/101/picture` (401 auth required)
- No anonymous snapshot access

### IP Camera (gSOAP)
- Port: 8084
- Minimal web interface, gSOAP/2.8 server header

## Camera Types Found in Database

### Hikvision
- Web ports: 80, 88, 580, 581, 8080, 8085, 5555
- RTSP port: 554
- RTSP path: `rtsp://ip:554/Streaming/Channels/101`
- ISAPI snapshot: `http://ip/ISAPI/Streaming/channels/101/picture` (401 auth required)
- Uses 302 redirect from HTTP:80 → HTTPS:443
- HTTPS serves meta refresh → `/webpages/index.html` (TP-Link AX80v1 firmware)
- Product detection works via fingerprint signatures on web UI

### Dahua / NETSurveillance
- Web ports: 80, 85
- RTSP port: 554
- RTSP path: `rtsp://ip:554/cam/realmonitor?channel=1&subtype=0`
- Server header: `uc-httpd 1.0.0`
- Login page: `/Login.htm` (MD5 challenge-response auth)
- `snap.jpg` returns static 36x25 placeholder (identical across all cameras)
- No anonymous snapshot access

### IP Camera (gSOAP)
- Port: 8084
- Minimal web interface, gSOAP/2.8 server header

## Authentication

Most cameras require authentication for:
- RTSP stream access (401 Unauthorized)
- ISAPI snapshot endpoints (401 Unauthorized)
- HTTP CGI endpoints (varies)

Exception: Axis cameras have anonymous snapshot access at `/axis-cgi/jpg/image.cgi`
