# 🛰️ Local Network Monitor

Ev ağınızdaki (LAN) tüm cihazları bulan, ayrıntılı tarayan ve sürekli izleyen, Docker'da çalışan bir web uygulaması.

## Özellikler

**Keşif ve envanter**
- ARP taraması ile ağdaki tüm cihazlar: IP, MAC, üretici (çevrimdışı OUI veritabanı), hostname
- mDNS/Bonjour, SSDP/UPnP ve NetBIOS ile cihazların kendini tanıtma bilgileri (model, isim, servisler)
- nmap ile açık portlar, servis sürümleri ve işletim sistemi tahmini
- Otomatik cihaz tipi tahmini (telefon, bilgisayar, TV, yazıcı, kamera, NAS, IoT…)
- Ad, konum, sahip ve not ekleme; “güvenilir” olarak işaretleme; CSV/JSON dışa aktarma
- **Gizli MAC birleştirme:** iOS/Android'in rastgele MAC adresleri hostname/mDNS adına göre aynı cihazda toplanır (elle birleştirme/ayırma da var)
- **Çoklu ağ/VLAN:** birden fazla subnet; router arkasındaki ağlar ping taramasıyla

**Güvenlik**
- Riskli servisler: Telnet, şifresiz FTP, anonim FTP, SMBv1, açık veritabanları, VNC/RDP, MQTT, Docker API…
- Varsayılan şifre kontrolü (nmap `http-default-accounts`)
- Bilinen zafiyetler (CVE) — nmap `vulners` scripti
- TLS sertifikası: süresi dolmuş / dolmak üzere / kendinden imzalı
- **Router/UPnP denetimi:** UPnP açık mı, internete açılmış port yönlendirmeleri neler
- **ARP spoofing tespiti:** ağ geçidinin MAC adresi değişirse anında kritik uyarı
- **Sahte DHCP tespiti:** ağda ikinci bir DHCP sunucusu olup olmadığı periyodik kontrol edilir
- **Güvenlik skoru (0–100)** ve geçmişi, her bulgu için öneri

**İzleme**
- Zamanlanmış hızlı keşif (varsayılan 5 dk) ve derin tarama (varsayılan 24 saat)
- Cihaz başına çevrimiçi zaman çizelgesi (24 saat / 7 gün), uptime yüzdesi ve gecikme
- **Tarama farkı:** iki derin tarama arasında açılan/kapanan portlar, değişen servis/OS, yeni/çözülen bulgular
- Ağ haritası (ağ geçidi merkezli, subnet ve tipe göre gruplu)
- Bildirimler ([Apprise](https://github.com/caronc/apprise/wiki) ile Telegram, e-posta, Discord, ntfy, Slack ve 100+ servis): yeni cihaz, yeni açık port, yüksek/kritik bulgu, ARP spoofing, sahte DHCP
- Haftalık HTML rapor (e-posta)

## Gereksinimler

- **Linux** bir makine: Raspberry Pi, NAS (Synology/QNAP/Unraid), mini PC veya sunucu
- Docker ve Docker Compose
- Makinenin taranacak ağa **kablolu/kablosuz doğrudan bağlı** olması

> ⚠️ **Docker Desktop (macOS / Windows) desteklenmez.** Uygulama `network_mode: host` ile ev ağını katman 2'de (ARP, mDNS, SSDP, DHCP) görmek zorundadır. Docker Desktop konteynerleri bir sanal makinede çalıştırdığı için bu mümkün değildir; cihazlar bulunmaz veya eksik görünür.

## Kurulum

```bash
git clone https://github.com/coraspirin/LocalNetworkMonitor.git
```

```bash
cd LocalNetworkMonitor
```

```bash
cp .env.example .env
```

`.env` dosyasında en azından `ADMIN_PASSWORD` ve `SECRET_KEY` değerlerini ayarlayın (`openssl rand -hex 32` ile rastgele bir anahtar üretebilirsiniz). Sonra:

```bash
docker compose up -d --build
```

Tarayıcıdan `http://<makinenin-ip-adresi>:8080` adresini açın. İlk açılışta otomatik olarak bir derin tarama başlar (ağ büyüklüğüne göre birkaç dakika sürer).

Loglar:

```bash
docker compose logs -f
```

Güncelleme:

```bash
git pull && docker compose up -d --build
```

Veriler `./data/netscanner.db` (SQLite) dosyasında saklanır.

## Yapılandırma

Ortam değişkenleri yalnızca ilk varsayılanları belirler; tarama aralıkları, bildirim adresleri, ağ listesi gibi ayarlar arayüzdeki **Ayarlar** sayfasından değiştirilebilir ve veritabanında saklanır.

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `PORT` | `8080` | Web arayüzü portu |
| `ADMIN_PASSWORD` | *(boş)* | Arayüz şifresi. Boşsa şifre sorulmaz (önerilmez) |
| `SECRET_KEY` | `change-me` | Oturum çerezlerini imzalama anahtarı |
| `SUBNETS` | *(otomatik)* | Virgülle CIDR listesi; boşsa bağlı ağlar otomatik bulunur |
| `TZ` | `Europe/Istanbul` | Saat dilimi |
| `APPRISE_URLS` | *(boş)* | Bildirim adresleri (virgülle) |
| `QUICK_INTERVAL_MIN` | `5` | Hızlı keşif aralığı (dakika) |
| `DEEP_INTERVAL_HOURS` | `24` | Derin tarama aralığı (saat, 0 = kapalı) |
| `TOP_PORTS` | `1000` | Derin taramada taranacak en yaygın port sayısı |
| `SCAN_CONCURRENCY` | `4` | Aynı anda derin taranan cihaz sayısı |
| `ENABLE_VULNERS` | `true` | CVE kontrolü (internet erişimi gerekir) |
| `ENABLE_WATCHDOG` | `true` | ARP spoofing izleyicisi |
| `DHCP_PROBE_INTERVAL_MIN` | `60` | Sahte DHCP kontrol aralığı (0 = kapalı) |
| `NOTIFY_ON_LEAVE` | `false` | Cihaz ayrıldığında da bildirim gönder |

### Bildirim örnekleri

- **Telegram:** `tgram://BOT_TOKEN/CHAT_ID` (BotFather ile bot oluşturun)
- **Gmail:** `mailtos://kullanici:uygulama-sifresi@gmail.com?to=ben@ornek.com` (Google “uygulama şifresi” gerekir)
- **ntfy:** `ntfy://ntfy.sh/benim-gizli-konum`
- **Discord:** `discord://webhook_id/webhook_token`

Ayarlar sayfasındaki **Test bildirimi gönder** düğmesiyle deneyebilirsiniz.

## Nasıl çalışır?

| Aşama | Ne yapar | Ne zaman |
|---|---|---|
| Hızlı keşif | ARP taraması (yönlendirilmiş ağlarda ping), ters DNS, mDNS; yeni/kaybolan cihazlar, IP değişimi, varlık örnekleri | Her 5 dk |
| Derin tarama | nmap `-sS -sV -O` + NSE scriptleri, SSDP/UPnP, güvenlik kuralları, router denetimi, diff, skor | Her 24 saat veya “Derin tara” |
| ARP izleyici | ARP yanıtlarını dinler, ağ geçidi MAC'i değişirse uyarır | Sürekli |
| DHCP yoklaması | DHCP DISCOVER gönderir (adres kiralamaz), gelen teklifleri sayar | Her 60 dk |

Bir cihaz art arda 3 hızlı keşifte görülmezse çevrimdışı sayılır. Telefonlar uyku modunda ARP'ye geç yanıt verebildiği için zaman çizelgesinde kısa boşluklar normaldir.

**Router'ı veya DHCP sunucusunu değiştirdiyseniz** Ayarlar → Sürekli izleme bölümünden yeni ağ geçidi MAC'ini / DHCP sunucusunu onaylayın; aksi halde yanlış alarm alırsınız.

## API

Tüm veriler REST API ile de erişilebilir; etkileşimli dokümantasyon: `http://<ip>:8080/api/docs`. Örnekler:

- `GET /api/devices` — cihaz listesi
- `GET /api/devices/{id}` — portlar, bulgular, MAC'ler, olaylar
- `POST /api/scans` `{"kind": "deep"}` — tarama başlat
- `GET /api/findings`, `GET /api/score`, `GET /api/diff?a=1&b=5`
- `GET /api/export/devices.csv`

## Geliştirme

```bash
pip install -r requirements-dev.txt
```

```bash
pytest
```

Yerelde çalıştırmak için (nmap kurulu olmalı; ARP ve OS tespiti için root gerekir):

```bash
DATA_DIR=./data sudo -E python -m app.main
```

Proje yapısı:

```
app/
  main.py          FastAPI uygulaması, kimlik doğrulama
  api.py, web.py   REST API ve HTML sayfaları
  pipeline.py      Tarama hattı (keşif → zenginleştirme → derin tarama → analiz)
  monitor.py       ARP/DHCP izleyicisinin uygulamaya bağlanması
  scheduler.py     Zamanlanmış işler
  scanner/         discovery, ports (nmap), services (mDNS/SSDP), security,
                   router (UPnP), watchdog (ARP/DHCP), analysis (diff/skor/MAC birleştirme)
  templates/, static/
tests/             Ayrıştırıcı, analiz, UPnP, pipeline ve web testleri
```

## Yasal uyarı

Bu aracı **yalnızca sahibi olduğunuz veya taramak için açık izniniz olan ağlarda** kullanın. Başkasına ait ağları izinsiz taramak birçok ülkede (Türkiye'de TCK 243–245 dahil) suç teşkil edebilir.
