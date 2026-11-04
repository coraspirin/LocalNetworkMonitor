# 🛰️ Local Network Monitor

🇹🇷 Türkçe · [🇬🇧 English](README.en.md)

Ev ağınızdaki (LAN) tüm cihazları bulan, ayrıntılı tarayan ve sürekli izleyen, Docker'da çalışan bir web uygulaması.

## Özellikler

**Keşif ve envanter**
- ARP taraması ile ağdaki tüm cihazlar: IP, MAC, üretici (çevrimdışı OUI veritabanı), hostname
- mDNS/Bonjour, SSDP/UPnP ve NetBIOS ile cihazların kendini tanıtma bilgileri (model, isim, servisler)
- nmap ile açık portlar, servis sürümleri ve işletim sistemi tahmini
- Otomatik cihaz tipi tahmini (telefon, bilgisayar, TV, yazıcı, kamera, NAS, IoT…)
- Ad, konum, sahip ve not ekleme; “güvenilir” olarak işaretleme; CSV/JSON dışa aktarma
- **Gizli MAC tanıma:** iOS/Android'in değişen (rastgele) MAC adresleri ad, DHCP parmak izi ve zamanlamaya göre aynı cihazda toplanır; emin olunamayan durumlarda tek tıkla onaylanan öneri sunulur (ayrıntılar aşağıda)
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
- **Türkçe / İngilizce arayüz:** üst menüdeki TR/EN düğmesiyle; bildirim ve raporlar varsayılan dilde

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

Derleme beklemek istemezseniz GitHub'da yayınlanan hazır imajı kullanabilirsiniz:

```bash
docker compose pull && docker compose up -d
```

Veriler `./data/netscanner.db` (SQLite) dosyasında saklanır. Önceki sürümlerin veritabanı açılışta otomatik yükseltilir.

## ZimaOS / CasaOS'a kurulum

Her `main` güncellemesinde GitHub Actions hazır imajı `ghcr.io/coraspirin/localnetworkmonitor:latest` adresine yayınlar (amd64 + arm64). ZimaOS'ta derleme yapılmaz, terminal de gerekmez.

**Arayüzden (önerilen)**

1. ZimaOS arayüzünde **App Store**'u açın, sağ üstteki **+** düğmesine basın ve **Install a customized app** seçin.
2. Sağ üstteki **Import** düğmesine basın ve [`zimaos/docker-compose.yml`](zimaos/docker-compose.yml) dosyasının içeriğini yapıştırın.
3. Ortam değişkenlerinde `ADMIN_PASSWORD` ve `SECRET_KEY` değerlerini doldurun. 8080 portu başka bir uygulamada kullanılıyorsa `PORT` değerini (ve web arayüzü portunu) değiştirin.
4. **Install**'a basın. Uygulama simgesi ana ekrana gelir; veriler `/DATA/AppData/localnetworkmonitor` klasöründe saklanır.

Güncellemek için uygulamanın menüsünden güncelleme/yeniden kurma seçeneğini kullanın; en yeni `latest` imajı çekilir.

**SSH ile (alternatif)**

```bash
sudo mkdir -p /DATA/AppData/localnetworkmonitor && cd /DATA/AppData/localnetworkmonitor
```

```bash
sudo curl -fsSLO https://raw.githubusercontent.com/coraspirin/LocalNetworkMonitor/main/zimaos/docker-compose.yml
```

Dosyadaki `ADMIN_PASSWORD` ve `SECRET_KEY` değerlerini doldurun (`sudo vi docker-compose.yml`), sonra:

```bash
sudo docker compose up -d
```

Güncelleme:

```bash
sudo docker compose pull && sudo docker compose up -d
```

> **Tek seferlik adım (repo sahibi için):** GitHub, Actions ile yayınlanan imaj paketini ilk seferde gizli (private) oluşturabilir. Bu durumda ZimaOS imajı çekemez ("denied" / "unauthorized" hatası). GitHub'da profil → **Packages** → `localnetworkmonitor` → **Package settings** → **Change visibility** → **Public** yapın.

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
| `DEFAULT_LANGUAGE` | `tr` | Varsayılan dil (`tr` / `en`): bildirimler, rapor ve dil seçmemiş ziyaretçiler |
| `RANDOM_MAC_NOTIFY` | `smart` | Gizli MAC'li yeni cihaz bildirimi: `smart`, `always`, `never` |

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
| ARP/DHCP izleyici | ARP yanıtlarını dinler (ağ geçidi MAC'i değişirse uyarır); DHCP isteklerinden cihaz adı ve parmak izi toplar | Sürekli |
| DHCP yoklaması | DHCP DISCOVER gönderir (adres kiralamaz), gelen teklifleri sayar | Her 60 dk |

Bir cihaz art arda 3 hızlı keşifte görülmezse çevrimdışı sayılır. Telefonlar uyku modunda ARP'ye geç yanıt verebildiği için zaman çizelgesinde kısa boşluklar normaldir.

**Router'ı veya DHCP sunucusunu değiştirdiyseniz** Ayarlar → Sürekli izleme bölümünden yeni ağ geçidi MAC'ini / DHCP sunucusunu onaylayın; aksi halde yanlış alarm alırsınız.

## Gizli (rastgele) MAC adresleri — iPhone / Android

iOS 14+ ve Android 10+ her Wi‑Fi ağı için "özel" bir MAC adresi kullanır; iOS 18'in **Dönüşümlü (Rotating)** modunda bu adres zaman zaman değişir ve cihaz adı da gizlenebilir. Uygulama bu cihazları şöyle takip eder:

1. **Tespit:** MAC adresindeki "yerel yönetimli" biti işaretli adresler *gizli* olarak etiketlenir.
2. **Kimlik ipuçları toplanır:**
   - mDNS/Bonjour host adı ve servis adları (ör. "Aylin'in iPhone'u"), ters DNS, NetBIOS
   - **Pasif DHCP dinleme:** cihaz ağa bağlanırken gönderdiği DHCP isteğindeki ad ve **parmak izi** (option 55 + 60). Bu parmak izi MAC değişse de aynı kalır ve işletim sistemi ailesini (Apple / Android / Windows / Linux) verir.
   - Açık portlar ve "eski adres kayboldu, hemen ardından yeni adres geldi" zamanlaması
3. **Puanlama:** aynı ad +70, aynı DHCP parmak izi +20, aynı portlar +10, aynı OS ailesi +5, rotasyon zamanlaması +15. Farklı adlar, farklı OS veya iki kaydın **aynı anda** ağda olması eşleşmeyi engeller.
   - **≥70 ve tek aday** → sessizce otomatik birleştirilir (MAC geçmişi cihaz sayfasında görünür).
   - **40–69 veya birden çok aday** → cihaz sayfasında **"Olası eşleşme"** kartı: *Aynı cihaz — birleştir* / *Farklı cihaz*. Reddedilen çift bir daha önerilmez.
4. **Bildirim (akıllı mod):** gizli MAC'li yeni cihaz için bildirim bir sonraki hızlı keşfe kadar bekletilir (DHCP/mDNS bilgisi gelsin diye). Otomatik birleştiyse bildirim gitmez; öneri varsa düşük önemli "muhtemelen bilinen bir cihazın yeni MAC'i", hiç eşleşme yoksa normal "yeni cihaz" uyarısı gönderilir.
5. **Temizlik:** 30 gün görülmeyen, adı/notu olmayan gizli MAC kayıtları otomatik arşivlenir (panoda "Arşivlenmiş" filtresiyle görülebilir).

> 💡 **En güvenilir çözüm:** iPhone/iPad'de *Ayarlar → Wi‑Fi → (ev ağı) ⓘ → Özel Wi‑Fi Adresi → **Sabit***; Android'de *Wi‑Fi ağ ayarları → Gizlilik → **Cihaz MAC'ini kullan***. Böylece adres ev ağınız için kalıcı olur.

Sınır: adını tamamen gizleyen, aynı model iki iPhone'un parmak izleri aynıdır; bu durumda uygulama kesin karar vermez, öneriyi size bırakır. DHCP dinleme için ARP izleyicinin açık olması ve cihazın (Wi‑Fi'ye yeni bağlanırken gönderdiği yayın) DHCP isteğinin bu makineye ulaşması gerekir.

## Dil

Arayüz Türkçe ve İngilizce'dir. Üst menüdeki **TR / EN** düğmesi seçimi tarayıcıda hatırlar; seçim yoksa tarayıcı dili, o da yoksa `DEFAULT_LANGUAGE` kullanılır. Bildirimler ve haftalık rapor her zaman varsayılan dilde gönderilir (Ayarlar → Genel). Bu sürümden önce kaydedilmiş olaylar, kaydedildikleri dilde (Türkçe) görünmeye devam eder; bulgular bir sonraki derin taramada güncellenip iki dilde görünür.

## API

Tüm veriler REST API ile de erişilebilir; etkileşimli dokümantasyon: `http://<ip>:8080/api/docs`. API hata mesajları istek dilindedir (`lang` çerezi veya `Accept-Language`). Örnekler:

- `GET /api/devices` — cihaz listesi
- `GET /api/devices/{id}` — portlar, bulgular, MAC'ler, olaylar
- `POST /api/scans` `{"kind": "deep"}` — tarama başlat
- `GET /api/findings`, `GET /api/score`, `GET /api/diff?a=1&b=5`
- `GET /api/suggestions`, `POST /api/suggestions/{id}/accept|reject` — gizli MAC eşleşme önerileri
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

Yeni arayüz metinleri `app/i18n.py` içine `(Türkçe, İngilizce)` çifti olarak eklenir; testler şablonlarda kullanılan her anahtarın var olduğunu ve İngilizce sayfalarda Türkçe metin kalmadığını kontrol eder.

Proje yapısı:

```
app/
  main.py          FastAPI uygulaması, kimlik doğrulama
  api.py, web.py   REST API ve HTML sayfaları
  pipeline.py      Tarama hattı (keşif → zenginleştirme → derin tarama → analiz)
  monitor.py       ARP/DHCP izleyicisinin uygulamaya bağlanması
  scheduler.py     Zamanlanmış işler
  i18n.py          Türkçe/İngilizce metin kataloğu
  scanner/         discovery, ports (nmap), services (mDNS/SSDP), security,
                   router (UPnP), watchdog (ARP/DHCP), dhcpfp (DHCP parmak izi),
                   analysis (diff/skor/gizli MAC eşleştirme)
  templates/, static/
tests/             Ayrıştırıcı, analiz, UPnP, pipeline, gizli MAC, i18n ve web testleri
```

## Yasal uyarı

Bu aracı **yalnızca sahibi olduğunuz veya taramak için açık izniniz olan ağlarda** kullanın. Başkasına ait ağları izinsiz taramak birçok ülkede (Türkiye'de TCK 243–245 dahil) suç teşkil edebilir.
