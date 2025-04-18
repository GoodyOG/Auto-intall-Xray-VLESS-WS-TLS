#!/bin/bash

# ==================================================
# Automatic Installation Script for Xray (VLESS + WS + TLS)
# Targeted at: Ubuntu 20.04+, Debian 10+, CentOS 7+
# Features: Two nodes (443 and 8443) with Certbot SSL, separate configs, systemd services, and QR codes.
# Includes TCP BBR for speed optimization.
# ==================================================

# === Configuration Variables ===
TRADING_PORT=443
FINANCE_PORT=8443
TRADING_NAME="Trading-Line"
FINANCE_NAME="Finance-Line"
LOG_BASE_DIR="/var/log/xray"
CONFIG_BASE_DIR="/etc/xray"
CERT_BASE_DIR="/etc/letsencrypt/live"

# === Helper Functions ===
Color_Off='\033[0m'; BGreen='\033[1;32m'; BYellow='\033[1;33m'; BRed='\033[1;31m'; BCyan='\033[1;36m'
log_info() { echo -e "${BCyan}[INFO] ${1}${Color_Off}"; }
log_warn() { echo -e "${BYellow}[WARN] ${1}${Color_Off}"; }
log_error() { echo -e "${BRed}[ERROR] ${1}${Color_Off}"; exit 1; }

# === Check for Root Privileges ===
if [[ "$EUID" -ne 0 ]]; then
  log_error "This script must be run with root privileges (sudo)."
fi

# === Determine QR Code Path ===
USER_HOME=""
if [[ -n "$SUDO_USER" ]]; then
    if command -v getent &> /dev/null; then
        USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    else
        log_warn "Command 'getent' not found."
    fi
fi
if [[ -z "$USER_HOME" ]]; then
    USER_HOME="/root"
    log_warn "Could not determine sudo user's home directory. Using ${USER_HOME} for QR codes."
fi
mkdir -p "$USER_HOME"

# === Start Script Execution ===
log_info "Starting Xray installation script for two nodes..."
log_info "Node 1: Trading-Line on port ${TRADING_PORT}"
log_info "Node 2: Finance-Line on port ${FINANCE_PORT}"

# === Determine OS and Install Dependencies ===
log_info "Determining operating system and installing dependencies..."
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VERSION_ID=$VERSION_ID
else
    log_error "Unable to determine operating system."
fi
log_info "Detected OS: $OS $VERSION_ID"

log_info "Updating package list and installing dependencies..."
case $OS in
    ubuntu|debian)
        apt update
        apt install -y curl wget unzip socat qrencode jq coreutils openssl bash-completion certbot
        ;;
    centos|almalinux|rocky)
        if [[ "$OS" == "centos" && "$VERSION_ID" == "7" ]]; then
             log_info "Installing EPEL repository for CentOS 7..."
             yum install -y epel-release || log_warn "Failed to install epel-release."
        fi
        yum update -y
        yum install -y curl wget unzip socat qrencode jq coreutils openssl bash-completion policycoreutils-python-utils util-linux certbot
        ;;
    *)
        log_error "Operating system $OS is not supported by this script."
        ;;
esac
log_info "Dependencies successfully installed."

# === Enable TCP BBR ===
log_info "Enabling TCP BBR for network speed optimization..."
BBR_CONF="/etc/sysctl.d/99-bbr.conf"
if ! grep -q "net.core.default_qdisc=fq" "$BBR_CONF" 2>/dev/null ; then
    echo "net.core.default_qdisc=fq" | tee "$BBR_CONF" > /dev/null
fi
if ! grep -q "net.ipv4.tcp_congestion_control=bbr" "$BBR_CONF" 2>/dev/null ; then
    echo "net.ipv4.tcp_congestion_control=bbr" | tee -a "$BBR_CONF" > /dev/null
fi
log_info "Applying sysctl settings for BBR..."
if sysctl -p "$BBR_CONF"; then
    log_info "TCP BBR settings successfully applied."
else
    log_warn "Failed to apply BBR settings. BBR may not be supported (requires kernel 4.9+)."
fi

# === Install Xray ===
log_info "Installing the latest stable version of Xray..."
if ! bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; then
    log_error "Error executing Xray installation script."
fi
if ! command -v xray &> /dev/null; then
    log_error "Command 'xray' not found after installation."
fi
log_info "Xray successfully installed: $(xray version | head -n 1)"

# === Input for Domains ===
log_info "Please enter the domain for Trading-Line (port ${TRADING_PORT}):"
read TRADING_DOMAIN
log_info "Please enter the domain for Finance-Line (port ${FINANCE_PORT}):"
read FINANCE_DOMAIN

# === Obtain SSL Certificates with Certbot ===
log_info "Obtaining SSL certificates using Certbot..."
certbot certonly --standalone --agree-tos --register-unsafely-without-email -d "$TRADING_DOMAIN"
certbot certonly --standalone --agree-tos --register-unsafely-without-email -d "$FINANCE_DOMAIN"
TRADING_CERT_DIR="${CERT_BASE_DIR}/${TRADING_DOMAIN}"
FINANCE_CERT_DIR="${CERT_BASE_DIR}/${FINANCE_DOMAIN}"
if [[ ! -f "${TRADING_CERT_DIR}/fullchain.pem" || ! -f "${TRADING_CERT_DIR}/privkey.pem" ]]; then
    log_error "Certbot failed to generate certificates for ${TRADING_DOMAIN}."
fi
if [[ ! -f "${FINANCE_CERT_DIR}/fullchain.pem" || ! -f "${FINANCE_CERT_DIR}/privkey.pem" ]]; then
    log_error "Certbot failed to generate certificates for ${FINANCE_DOMAIN}."
fi
log_info "SSL certificates obtained successfully."

# === Generate UUIDs ===
TRADING_UUID=$(xray uuid)
FINANCE_UUID=$(xray uuid)
log_info "Generated UUID for Trading-Line: ${TRADING_UUID}"
log_info "Generated UUID for Finance-Line: ${FINANCE_UUID}"

# === Configure Firewall ===
log_info "Configuring firewall for ports ${TRADING_PORT}/tcp and ${FINANCE_PORT}/tcp..."
if command -v ufw &> /dev/null; then
    log_info "Detected UFW. Opening ports..."
    ufw allow ${TRADING_PORT}/tcp || log_warn "Failed to allow port ${TRADING_PORT}/tcp."
    ufw allow ${FINANCE_PORT}/tcp || log_warn "Failed to allow port ${FINANCE_PORT}/tcp."
    if ufw status | grep -qw active; then
        ufw reload || log_error "Failed to reload UFW rules."
    else
        log_warn "UFW is inactive. Rules added but not enforced."
    fi
elif command -v firewall-cmd &> /dev/null; then
    log_info "Detected firewalld. Opening ports..."
    firewall-cmd --permanent --add-port=${TRADING_PORT}/tcp || log_warn "Failed to add port ${TRADING_PORT}/tcp."
    firewall-cmd --permanent --add-port=${FINANCE_PORT}/tcp || log_warn "Failed to add port ${FINANCE_PORT}/tcp."
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --reload || log_error "Failed to reload firewalld rules."
    else
        log_warn "firewalld is inactive. Rules added but not enforced."
    fi
    if [[ -f /usr/sbin/sestatus ]] && sestatus | grep -q "enabled"; then
        log_info "Configuring SELinux for ports..."
        semanage port -a -t http_port_t -p tcp ${TRADING_PORT} || log_warn "Failed to configure SELinux for port ${TRADING_PORT}."
        semanage port -a -t http_port_t -p tcp ${FINANCE_PORT} || log_warn "Failed to configure SELinux for port ${FINANCE_PORT}."
    fi
else
    log_warn "No UFW or firewalld detected. Ensure ports ${TRADING_PORT}/tcp and ${FINANCE_PORT}/tcp are open manually."
fi

# === Create Trading-Line Configuration ===
TRADING_CONFIG_DIR="${CONFIG_BASE_DIR}/trading"
TRADING_LOG_DIR="${LOG_BASE_DIR}/trading"
TRADING_WS_PATH="/$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12)"
mkdir -p "$TRADING_CONFIG_DIR" "$TRADING_LOG_DIR"
chown nobody:nogroup "$TRADING_LOG_DIR" || log_warn "Failed to set ownership of ${TRADING_LOG_DIR}."
cat > "${TRADING_CONFIG_DIR}/config.json" << EOF
{
  "log": { "loglevel": "warning", "access": "${TRADING_LOG_DIR}/access.log", "error": "${TRADING_LOG_DIR}/error.log" },
  "dns": { "servers": ["https://1.1.1.1/dns-query", "8.8.8.8", "9.9.9.9"], "queryStrategy": "UseIP" },
  "inbounds": [ {
      "port": ${TRADING_PORT}, "protocol": "vless",
      "settings": { "clients": [ { "id": "${TRADING_UUID}" } ], "decryption": "none" },
      "streamSettings": {
        "network": "ws", "security": "tls",
        "tlsSettings": { "alpn": ["http/1.1"], "certificates": [ { "certificateFile": "${TRADING_CERT_DIR}/fullchain.pem", "keyFile": "${TRADING_CERT_DIR}/privkey.pem" } ] },
        "wsSettings": { "path": "${TRADING_WS_PATH}", "headers": { "Host": "${TRADING_DOMAIN}" } }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
  } ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" } ]
}
EOF
log_info "Trading-Line configuration created at ${TRADING_CONFIG_DIR}/config.json."

# === Create Finance-Line Configuration ===
FINANCE_CONFIG_DIR="${CONFIG_BASE_DIR}/finance"
FINANCE_LOG_DIR="${LOG_BASE_DIR}/finance"
FINANCE_WS_PATH="/$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12)"
mkdir -p "$FINANCE_CONFIG_DIR" "$FINANCE_LOG_DIR"
chown nobody:nogroup "$FINANCE_LOG_DIR" || log_warn "Failed to set ownership of ${FINANCE_LOG_DIR}."
cat > "${FINANCE_CONFIG_DIR}/config.json" << EOF
{
  "log": { "loglevel": "warning", "access": "${FINANCE_LOG_DIR}/access.log", "error": "${FINANCE_LOG_DIR}/error.log" },
  "dns": { "servers": ["https://1.1.1.1/dns-query", "8.8.8.8", "9.9.9.9"], "queryStrategy": "UseIP" },
  "inbounds": [ {
      "port": ${FINANCE_PORT}, "protocol": "vless",
      "settings": { "clients": [ { "id": "${FINANCE_UUID}" } ], "decryption": "none" },
      "streamSettings": {
        "network": "ws", "security": "tls",
        "tlsSettings": { "alpn": ["http/1.1"], "certificates": [ { "certificateFile": "${FINANCE_CERT_DIR}/fullchain.pem", "keyFile": "${FINANCE_CERT_DIR}/privkey.pem" } ] },
        "wsSettings": { "path": "${FINANCE_WS_PATH}", "headers": { "Host": "${FINANCE_DOMAIN}" } }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
  } ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" } ]
}
EOF
log_info "Finance-Line configuration created at ${FINANCE_CONFIG_DIR}/config.json."

# === Validate Configurations ===
log_info "Validating Xray configurations..."
/usr/local/bin/xray -test -config "${TRADING_CONFIG_DIR}/config.json" || log_error "Trading-Line configuration is invalid."
/usr/local/bin/xray -test -config "${FINANCE_CONFIG_DIR}/config.json" || log_error "Finance-Line configuration is invalid."
log_info "Both configurations are valid."

# === Set Up Systemd Services ===
log_info "Setting up systemd services for both nodes..."
cat > /lib/systemd/system/xray-trading.service << EOF
[Unit]
Description=Xray Trading-Line Service
After=network.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/xray run -config ${TRADING_CONFIG_DIR}/config.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

cat > /lib/systemd/system/xray-finance.service << EOF
[Unit]
Description=Xray Finance-Line Service
After=network.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/xray run -config ${FINANCE_CONFIG_DIR}/config.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray-trading xray-finance || log_warn "Failed to enable one or both services."
systemctl restart xray-trading xray-finance || log_error "Failed to start one or both services."
log_info "Systemd services configured and started."

# === Generate VLESS Links and QR Codes ===
log_info "Generating VLESS links and QR codes..."
TRADING_WS_PATH_ENCODED=$(printf %s "${TRADING_WS_PATH}" | jq -sRr @uri)
FINANCE_WS_PATH_ENCODED=$(printf %s "${FINANCE_WS_PATH}" | jq -sRr @uri)
TRADING_VLESS_LINK="vless://${TRADING_UUID}@${TRADING_DOMAIN}:${TRADING_PORT}?type=ws&path=${TRADING_WS_PATH_ENCODED}&security=tls&sni=${TRADING_DOMAIN}#${TRADING_NAME}"
FINANCE_VLESS_LINK="vless://${FINANCE_UUID}@${FINANCE_DOMAIN}:${FINANCE_PORT}?type=ws&path=${FINANCE_WS_PATH_ENCODED}&security=tls&sni=${FINANCE_DOMAIN}#${FINANCE_NAME}"

qrencode -o "${USER_HOME}/trading_qr.png" "$TRADING_VLESS_LINK" || log_warn "Failed to generate Trading-Line QR code."
qrencode -o "${USER_HOME}/finance_qr.png" "$FINANCE_VLESS_LINK" || log_warn "Failed to generate Finance-Line QR code."
if [[ -n "$SUDO_USER" && "$USER_HOME" != "/root" ]]; then
    chown "$SUDO_USER":"$(id -gn "$SUDO_USER")" "${USER_HOME}/trading_qr.png" "${USER_HOME}/finance_qr.png" || log_warn "Failed to set QR code ownership."
fi
log_info "QR codes saved: ${USER_HOME}/trading_qr.png and ${USER_HOME}/finance_qr.png"

# === Final Output ===
log_info "=================================================="
log_info "${BGreen} Xray Installation Completed for Two Nodes! ${Color_Off}"
log_info "=================================================="
echo -e "${BYellow}Trading-Line:${Color_Off}"
echo -e "  Domain: ${TRADING_DOMAIN}"
echo -e "  Port: ${TRADING_PORT}"
echo -e "  UUID: ${TRADING_UUID}"
echo -e "  VLESS Link: ${TRADING_VLESS_LINK}"
echo -e "  QR Code: ${USER_HOME}/trading_qr.png"
echo ""
echo -e "${BYellow}Finance-Line:${Color_Off}"
echo -e "  Domain: ${FINANCE_DOMAIN}"
echo -e "  Port: ${FINANCE_PORT}"
echo -e "  UUID: ${FINANCE_UUID}"
echo -e "  VLESS Link: ${FINANCE_VLESS_LINK}"
echo -e "  QR Code: ${USER_HOME}/finance_qr.png"
echo ""
echo -e "${BCyan}Service Management:${Color_Off}"
echo -e "  Trading-Line: systemctl {start|stop|restart|status} xray-trading"
echo -e "  Finance-Line: systemctl {start|stop|restart|status} xray-finance"
echo -e "  Logs: ${LOG_BASE_DIR}/{trading,finance}/{access,error}.log"
echo ""
log_info "Installation complete. Enjoy your VLESS nodes!"

exit 0
