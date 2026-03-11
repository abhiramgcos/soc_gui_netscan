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
    kmod \
    procps \
    psmisc \
    inotify-tools \
    libnotify-bin \
    python3 \
    python-is-python3 \
    && rm -rf /var/lib/apt/lists/*

# ── Install EMBA into image ───────────────────
ARG EMBA_GIT_REF=master
ENV EMBA_HOME=/opt/emba
ENV EMBA_PATH=/opt/emba/emba
ENV USER=root
ENV SUDO_USER=root
ENV LOGNAME=root
RUN git clone --depth 1 --branch ${EMBA_GIT_REF} https://github.com/e-m-b-a/emba.git /opt/emba \
        && if [ ! -f /etc/apt/sources.list ]; then \
                 printf "deb http://deb.debian.org/debian bookworm main\n" > /etc/apt/sources.list; \
                 printf "deb http://deb.debian.org/debian bookworm-updates main\n" >> /etc/apt/sources.list; \
                 printf "deb http://deb.debian.org/debian-security bookworm-security main\n" >> /etc/apt/sources.list; \
             fi \
    && chmod +x /opt/emba/installer.sh /opt/emba/emba \
    && cd /opt/emba \
    && SUDO_USER=root USER=root LOGNAME=root HOME=/root yes | ./installer.sh -s -D

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
