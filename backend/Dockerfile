FROM python:3.12-slim-bookworm

# ── System deps for nmap, rustscan, arp-scan ────
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nmap \
    arp-scan \
    net-tools \
    iproute2 \
    iputils-ping \
    curl \
    gcc \
    libpq-dev \
    wget \
    sudo \
    file \
    binutils \
    xxd \
    unzip \
    p7zip-full \
    binwalk \
    bash \
    coreutils \
    findutils \
    grep \
    gawk \
    git \
    docker.io \
    kmod \
    procps \
    psmisc \
    inotify-tools \
    libnotify-bin \
    python3 \
    python-is-python3 \
    && rm -rf /var/lib/apt/lists/*

# ── Install RustScan ────────────────────────────
COPY rustscan.deb /tmp/rustscan.deb
RUN dpkg -i /tmp/rustscan.deb || apt-get install -fy && \
    rm /tmp/rustscan.deb

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ── Run as root for network scanning privileges ─
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001", "--reload"]
