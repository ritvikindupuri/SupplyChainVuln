FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    tshark tcpdump \
    nmap netcat-openbsd iproute2 iptables \
    curl jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /agent
COPY requirements.txt .
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir -r requirements.txt

COPY agent.py capture.py attack_detector.py ./

ENV PATH="/venv/bin:$PATH"
CMD ["python3", "-u", "agent.py"]
