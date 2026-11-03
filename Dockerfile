FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data \
    TZ=Europe/Istanbul

# nmap: port/servis/OS taraması ve NSE scriptleri (+ OUI üretici veritabanı)
# libpcap: scapy ile ARP taraması, ARP izleme ve DHCP yoklaması
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap libpcap0.8 iproute2 tzdata ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8080\")}/api/health', timeout=4)" || exit 1

# Ham soket (ARP, SYN taraması, OS tespiti) için root + NET_RAW/NET_ADMIN gerekir
CMD ["python", "-m", "app.main"]
