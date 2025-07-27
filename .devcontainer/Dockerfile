# Use official Python image as base (MCR has persistent connectivity issues)
FROM python:3.12-bullseye

# Install basic development tools first
RUN apt-get update \
  && export DEBIAN_FRONTEND=noninteractive \
  && apt-get install -y \
    git \
    curl \
    wget \
    sudo \
    build-essential \
    ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install basic network tools
RUN apt-get update \
  && export DEBIAN_FRONTEND=noninteractive \
  && apt-get install -y \
    nmap \
    netcat-traditional \
    dnsutils \
    net-tools \
    iproute2 \
    traceroute \
    whois \
    telnet \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Create vscode user (standard in devcontainers)
RUN groupadd --gid 1000 vscode \
  && useradd --uid 1000 --gid vscode --shell /bin/bash --create-home vscode \
  && echo vscode ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/vscode \
  && chmod 0440 /etc/sudoers.d/vscode

# Install Python packages
RUN pip install --upgrade pip \
  && pip install \
    python-nmap \
    scapy \
    requests \
    beautifulsoup4 \
    paramiko \
    netaddr \
    dnspython

# Set the default user to vscode (like Microsoft devcontainers)
USER vscode
WORKDIR /workspaces/devcontainer-python
