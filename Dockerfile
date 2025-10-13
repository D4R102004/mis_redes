FROM python:3.12-slim

WORKDIR /app

# --- Install system dependencies ---
# tk: for GUI; iproute2, net-tools: for debugging interfaces
RUN apt-get update && apt-get install -y \
    tk \
    net-tools \
    iproute2 \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# --- Copy project ---
COPY . /app

# --- Make entrypoint executable ---
RUN chmod +x /app/docker-entrypoint.sh

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
