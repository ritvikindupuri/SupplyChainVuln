FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    nmap netcat-openbsd hping3 hydra \
    curl wget dnsutils iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /engine
COPY requirements.txt .
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir -r requirements.txt

COPY engine.py ./

ENV PATH="/venv/bin:$PATH"
CMD ["python3", "-u", "engine.py"]
