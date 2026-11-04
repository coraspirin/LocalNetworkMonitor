# 🛰️ Local Network Monitor

[🇹🇷 Türkçe](README.md) · 🇬🇧 English

A Docker-based web application that discovers every device on your home network (LAN), scans them in detail and keeps monitoring them.

## Features

**Discovery and inventory**
- Every device on the network via ARP: IP, MAC, vendor (offline OUI database), hostname
- Self-announced information via mDNS/Bonjour, SSDP/UPnP and NetBIOS (model, name, services)
- Open ports, service versions and OS detection with nmap
- Automatic device type detection (phone, computer, TV, printer, camera, NAS, IoT…)
- Name, location, owner and notes; mark devices as “trusted”; CSV/JSON export
- **Private MAC recognition:** the changing (randomized) MAC addresses of iOS/Android devices are linked to the same device using names, DHCP fingerprints and timing; when unsure, a one-click suggestion is shown (details below)
- **Multiple networks/VLANs:** several subnets; networks behind a router are ping-scanned

**Security**
- Risky services: Telnet, plain FTP, anonymous FTP, SMBv1, exposed databases, VNC/RDP, MQTT, Docker API…
- Default credential check (nmap `http-default-accounts`)
- Known vulnerabilities (CVE) — nmap `vulners` script
- TLS certificates: expired / expiring / self-signed
- **Router/UPnP audit:** is UPnP enabled, which ports are forwarded to the internet
- **ARP spoofing detection:** instant critical alert if the gateway's MAC address changes
- **Rogue DHCP detection:** periodic check for a second DHCP server on the network
- **Security score (0–100)** with history and a recommendation for every finding

**Monitoring**
- Scheduled quick scan (default 5 min) and deep scan (default 24 h)
- Per-device online timeline (24 h / 7 days), uptime percentage and latency
- **Scan diff:** opened/closed ports, changed services/OS, new/resolved findings between two deep scans
- Network map (gateway-centered, grouped by subnet and type)
- Notifications via [Apprise](https://github.com/caronc/apprise/wiki) (Telegram, e-mail, Discord, ntfy, Slack and 100+ services): new device, newly opened port, high/critical finding, ARP spoofing, rogue DHCP
- Weekly HTML report (e-mail)
- **Turkish / English interface:** TR/EN switch in the top bar; notifications and reports use the default language

## Requirements

- A **Linux** machine: Raspberry Pi, NAS (Synology/QNAP/Unraid), mini PC or server
- Docker and Docker Compose
- The machine must be **directly connected** (wired or wireless) to the network you want to scan

> ⚠️ **Docker Desktop (macOS / Windows) is not supported.** The app needs `network_mode: host` to see the home network at layer 2 (ARP, mDNS, SSDP, DHCP). Docker Desktop runs containers inside a virtual machine, so devices would be missing or incomplete.

## Installation

```bash
git clone https://github.com/coraspirin/LocalNetworkMonitor.git
```

```bash
cd LocalNetworkMonitor
```

```bash
cp .env.example .env
```

Set at least `ADMIN_PASSWORD` and `SECRET_KEY` in `.env` (generate a random key with `openssl rand -hex 32`). For an English interface and English notifications set `DEFAULT_LANGUAGE=en`. Then:

```bash
docker compose up -d --build
```

Open `http://<machine-ip>:8080` in your browser. A deep scan starts automatically on first launch (takes a few minutes depending on network size).

Logs:

```bash
docker compose logs -f
```

Update:

```bash
git pull && docker compose up -d --build
```

To skip the build, use the ready-made image published on GitHub:

```bash
docker compose pull && docker compose up -d
```

Data is stored in `./data/netscanner.db` (SQLite). Databases from earlier versions are upgraded automatically on startup.

## Installing on ZimaOS / CasaOS

On every `main` update GitHub Actions publishes a ready-made image to `ghcr.io/coraspirin/localnetworkmonitor:latest` (amd64 + arm64). Nothing is built on ZimaOS and no terminal is needed.

**From the web UI (recommended)**

1. In the ZimaOS UI open the **App Store**, click **+** in the top right and choose **Install a customized app**.
2. Click **Import** in the top right and paste the contents of [`zimaos/docker-compose.yml`](zimaos/docker-compose.yml).
3. Fill in `ADMIN_PASSWORD` and `SECRET_KEY` in the environment variables. If port 8080 is used by another app, change `PORT` (and the web UI port).
4. Click **Install**. The app icon appears on the dashboard; data is stored in `/DATA/AppData/localnetworkmonitor`.

To update, use the app's update/reinstall option; the newest `latest` image is pulled.

**Over SSH (alternative)**

```bash
sudo mkdir -p /DATA/AppData/localnetworkmonitor && cd /DATA/AppData/localnetworkmonitor
```

```bash
sudo curl -fsSLO https://raw.githubusercontent.com/coraspirin/LocalNetworkMonitor/main/zimaos/docker-compose.yml
```

Fill in `ADMIN_PASSWORD` and `SECRET_KEY` in the file (`sudo vi docker-compose.yml`), then:

```bash
sudo docker compose up -d
```

Update:

```bash
sudo docker compose pull && sudo docker compose up -d
```

> **One-time step (for the repository owner):** GitHub may create the package published by Actions as private the first time. ZimaOS then cannot pull the image ("denied" / "unauthorized"). On GitHub go to your profile → **Packages** → `localnetworkmonitor` → **Package settings** → **Change visibility** → **Public**.

## Configuration

Environment variables only set the initial defaults; scan intervals, notification URLs, the network list and the language can be changed on the **Settings** page and are stored in the database.

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Web interface port |
| `ADMIN_PASSWORD` | *(empty)* | Interface password. No login if empty (not recommended) |
| `SECRET_KEY` | `change-me` | Key used to sign session cookies |
| `SUBNETS` | *(auto)* | Comma-separated CIDR list; connected networks are detected if empty |
| `TZ` | `Europe/Istanbul` | Time zone |
| `DEFAULT_LANGUAGE` | `tr` | Default language (`tr` / `en`): notifications, report and visitors without a choice |
| `APPRISE_URLS` | *(empty)* | Notification URLs (comma-separated) |
| `QUICK_INTERVAL_MIN` | `5` | Quick scan interval (minutes) |
| `DEEP_INTERVAL_HOURS` | `24` | Deep scan interval (hours, 0 = off) |
| `TOP_PORTS` | `1000` | Number of most common ports to scan |
| `SCAN_CONCURRENCY` | `4` | Devices deep-scanned in parallel |
| `ENABLE_VULNERS` | `true` | CVE check (needs internet access) |
| `ENABLE_WATCHDOG` | `true` | ARP spoofing watcher (also collects DHCP fingerprints) |
| `DHCP_PROBE_INTERVAL_MIN` | `60` | Rogue DHCP check interval (0 = off) |
| `NOTIFY_ON_LEAVE` | `false` | Also notify when a device leaves |
| `RANDOM_MAC_NOTIFY` | `smart` | Notifications for new private-MAC devices: `smart`, `always`, `never` |

### Notification examples

- **Telegram:** `tgram://BOT_TOKEN/CHAT_ID` (create a bot with BotFather)
- **Gmail:** `mailtos://user:app-password@gmail.com?to=me@example.com` (needs a Google “app password”)
- **ntfy:** `ntfy://ntfy.sh/my-secret-topic`
- **Discord:** `discord://webhook_id/webhook_token`

Use **Send test notification** on the Settings page to try it.

## How it works

| Stage | What it does | When |
|---|---|---|
| Quick scan | ARP sweep (ping on routed networks), reverse DNS, mDNS; new/missing devices, IP changes, presence samples, private-MAC matching | Every 5 min |
| Deep scan | nmap `-sS -sV -O` + NSE scripts, SSDP/UPnP, security rules, router audit, diff, score | Every 24 h or “Deep scan” |
| ARP/DHCP watcher | Listens to ARP replies (alerts if the gateway MAC changes); collects device names and fingerprints from DHCP requests | Continuous |
| DHCP probe | Sends a DHCP DISCOVER (no lease is taken) and counts the offers | Every 60 min |

A device counts as offline after it is missed in 3 consecutive quick scans. Phones may answer ARP late while asleep, so short gaps in the timeline are normal.

**If you replaced your router or DHCP server**, confirm the new gateway MAC / DHCP server under Settings → Continuous monitoring, otherwise you'll get false alarms.

## Private (randomized) MAC addresses — iPhone / Android

iOS 14+ and Android 10+ use a “private” MAC address per Wi‑Fi network; in iOS 18's **Rotating** mode this address changes from time to time and the device name may be hidden as well. The app tracks such devices like this:

1. **Detection:** addresses with the “locally administered” bit set are labelled *private*.
2. **Identity hints are collected:**
   - mDNS/Bonjour host and service names (e.g. “Aylin's iPhone”), reverse DNS, NetBIOS
   - **Passive DHCP listening:** the name and **fingerprint** (option 55 + 60) in the DHCP request a device sends when it joins. The fingerprint stays the same when the MAC changes and reveals the OS family (Apple / Android / Windows / Linux).
   - Open ports and the timing “old address vanished, new address appeared right after”
3. **Scoring:** same name +70, same DHCP fingerprint +20, same ports +10, same OS family +5, rotation timing +15. Different names, a different OS, or both records being on the network **at the same time** prevent a match.
   - **≥70 with a single candidate** → merged automatically and silently (the MAC history is shown on the device page).
   - **40–69 or several candidates** → a **“Possible match”** card on the device page: *Same device — merge* / *Different device*. A rejected pair is never suggested again.
4. **Notifications (smart mode):** the notification for a new private-MAC device is held until the next quick scan (so DHCP/mDNS data can arrive). Nothing is sent if it was merged automatically; a low-severity “probably a known device's new MAC” is sent if there is a suggestion; otherwise the normal “new device” alert is sent.
5. **Cleanup:** private-MAC records not seen for 30 days and without a name/notes are archived automatically (visible with the “Archived” filter on the dashboard).

> 💡 **Most reliable fix:** on iPhone/iPad go to *Settings → Wi‑Fi → (home network) ⓘ → Private Wi‑Fi Address → **Fixed***; on Android *Wi‑Fi network settings → Privacy → **Use device MAC***. The address then stays constant on your home network.

Limitation: two iPhones of the same model that both hide their names have identical fingerprints; in that case the app does not decide on its own and leaves the suggestion to you. DHCP listening requires the ARP watcher to be enabled and the device's DHCP request (broadcast when it joins Wi‑Fi) to reach this machine.

## Language

The interface is available in Turkish and English. The **TR / EN** switch in the top bar remembers your choice in the browser; without a choice the browser language is used, then `DEFAULT_LANGUAGE`. Notifications and the weekly report are always sent in the default language (Settings → General). Events recorded before this version keep the language they were recorded in (Turkish); findings are refreshed on the next deep scan and then appear in both languages.

## API

All data is available through a REST API; interactive docs: `http://<ip>:8080/api/docs`. API error messages follow the request language (`lang` cookie or `Accept-Language`). Examples:

- `GET /api/devices` — device list
- `GET /api/devices/{id}` — ports, findings, MACs, events, match suggestions
- `POST /api/scans` `{"kind": "deep"}` — start a scan
- `GET /api/findings`, `GET /api/score`, `GET /api/diff?a=1&b=5`
- `GET /api/suggestions`, `POST /api/suggestions/{id}/accept|reject` — private-MAC match suggestions
- `GET /api/export/devices.csv`

## Development

```bash
pip install -r requirements-dev.txt
```

```bash
pytest
```

To run locally (nmap must be installed; ARP and OS detection need root):

```bash
DATA_DIR=./data sudo -E python -m app.main
```

New interface texts are added to `app/i18n.py` as a `(Turkish, English)` pair; the tests check that every key used in the templates exists and that English pages contain no Turkish text.

## Legal notice

Use this tool **only on networks you own or have explicit permission to scan**. Scanning other people's networks without permission is illegal in many countries.
