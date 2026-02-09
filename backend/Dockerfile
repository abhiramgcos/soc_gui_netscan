FROM python:3.12-slim

# ── System deps for nmap, rustscan, arp-scan ────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    arp-scan \
    net-tools \
    iputils-ping \
    curl \
    gcc \
    libpq-dev \
    wget \
    sudo \
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
