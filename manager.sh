#!/bin/bash

readonly XRAY_DIR="/usr/local/etc/xray"
readonly INFO_FILE="$XRAY_DIR/install_info.txt"
readonly CONFIG_FILE="$XRAY_DIR/config.json"
readonly CONFIG_HASH_FILE="$XRAY_DIR/.config_hash"
readonly BACKUP_DIR="$XRAY_DIR/backup"
readonly SUBS_DIR="/var/www/html/subs"
readonly CERT_BASE="/etc/letsencrypt/live"

readonly VERSION="3.2"

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly GRAY='\033[0;90m'
readonly NC='\033[0m'

logInfo() { echo -e "${YELLOW}• $1${NC}" >&2; }
logSuccess() { echo -e "${GREEN}✓ $1${NC}" >&2; }
logError() { echo -e "${RED}✕ $1${NC}" >&2; }
logWarning() { echo -e "${YELLOW}⚠ $1${NC}" >&2; }

requireRoot() {
    if [ "$EUID" -ne 0 ]; then
        logError "Run as root."
        exit 1
    fi
}

toBase64() {
    echo -n "$1" | base64 | tr '+/' '-_' | tr -d '='
}

generateUuid() {
    cat /proc/sys/kernel/random/uuid
}

generateRandomSuffix() {
    head /dev/urandom | tr -dc 'a-z0-9' | head -c 5
}

validateUsername() {
    local name="$1"
    [[ "$name" =~ ^[a-zA-Z0-9_-]{2,32}$ ]]
}

validateDomain() {
    local domain="$1"
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]
}

commandExists() {
    command -v "$1" &>/dev/null
}

fileExists() {
    [ -f "$1" ]
}

dirExists() {
    [ -d "$1" ]
}

showQr() {
    local data="$1"
    local label="$2"
    echo "" >&2
    echo -e "${YELLOW}QR: $label${NC}" >&2
    if commandExists qrencode; then
        qrencode -t ANSIUTF8 "$data" >&2
    else
        logWarning "qrencode not installed"
    fi
    echo "" >&2
}

safeJsonUpdate() {
    local file="$1"
    local jqFilter="$2"
    shift 2
    
    local tmpFile=$(mktemp)
    if jq "$jqFilter" "$@" "$file" > "$tmpFile" && [ -s "$tmpFile" ]; then
        mv "$tmpFile" "$file"
        return 0
    else
        rm -f "$tmpFile"
        return 1
    fi
}

getInstallInfo() {
    local key="$1"
    if fileExists "$INFO_FILE"; then
        grep "^${key}=" "$INFO_FILE" 2>/dev/null | cut -d'=' -f2
    fi
}

setInstallInfo() {
    local key="$1"
    local value="$2"
    
    mkdir -p "$XRAY_DIR"
    
    if fileExists "$INFO_FILE" && grep -q "^${key}=" "$INFO_FILE"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$INFO_FILE"
    else
        echo "${key}=${value}" >> "$INFO_FILE"
    fi
}

getDomain() {
    getInstallInfo "domain" || echo "-"
}

getSubUri() {
    getInstallInfo "subUri"
}

getCertPath() {
    echo "$CERT_BASE/$(getDomain)"
}

isXrayInstalled() {
    fileExists "/usr/local/bin/xray"
}

isServiceRunning() {
    systemctl is-active --quiet "$1"
}

getStatus() {
    if ! isXrayInstalled; then
        echo "not_installed"
    elif isServiceRunning xray; then
        echo "running"
    else
        echo "stopped"
    fi
}

getUserCount() {
    if fileExists "$CONFIG_FILE"; then
        jq -r '.inbounds[0].settings.clients | length' "$CONFIG_FILE" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

getXrayVersion() {
    /usr/local/bin/xray version 2>/dev/null | head -n1 | awk '{print $2}'
}

getLatestXrayVersion() {
    curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name' | tr -d 'v'
}

generateInbound() {
    local port="$1"
    local certPath="$2"
    
    cat <<EOF
{
  "port": $port,
  "protocol": "vless",
  "settings": {
    "clients": [],
    "decryption": "none",
    "fallbacks": [{ "dest": 8080 }]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "certificates": [{
        "certificateFile": "$certPath/fullchain.pem",
        "keyFile": "$certPath/privkey.pem"
      }],
      "minVersion": "1.2",
      "alpn": ["http/1.1", "h2"]
    }
  },
  "sniffing": {
    "enabled": true,
    "destOverride": ["http", "tls"]
  }
}
EOF
}

generateClient() {
    local uuid="$1"
    local email="$2"
    local flow="${3:-xtls-rprx-vision}"
    
    cat <<EOF
{
  "id": "$uuid",
  "flow": "$flow",
  "level": 0,
  "email": "$email"
}
EOF
}

generateOutboundWarp() {
    local privateKey="$1"
    local addresses="$2"
    
    cat <<EOF
{
  "tag": "warp",
  "protocol": "wireguard",
  "settings": {
    "secretKey": "$privateKey",
    "address": [$addresses],
    "peers": [{
      "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "endpoint": "engage.cloudflareclient.com:2408",
      "keepAlive": 15
    }],
    "mtu": 1280
  }
}
EOF
}

generateOutboundDirect() {
    echo '{ "tag": "direct", "protocol": "freedom" }'
}

generateOutboundBlock() {
    echo '{ "tag": "block", "protocol": "blackhole" }'
}

generateRouting() {
    cat <<EOF
{
  "domainStrategy": "IPIfNonMatch",
  "rules": [
    { "type": "field", "outboundTag": "block", "ip": ["geoip:private"] }
  ]
}
EOF
}

buildConfig() {
    local certPath="$1"
    local warpKey="$2"
    local warpAddresses="$3"
    
    local inbound=$(generateInbound 443 "$certPath")
    local routing=$(generateRouting)
    
    local outbounds
    if [ -n "$warpKey" ]; then
        local warp=$(generateOutboundWarp "$warpKey" "$warpAddresses")
        local direct=$(generateOutboundDirect)
        local block=$(generateOutboundBlock)
        outbounds="[$warp, $block, $direct]"
    else
        local direct=$(generateOutboundDirect)
        local block=$(generateOutboundBlock)
        outbounds="[$direct, $block]"
    fi
    
    cat <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [$inbound],
  "outbounds": $outbounds,
  "routing": $routing
}
EOF
}

saveConfig() {
    local configJson="$1"
    mkdir -p "$XRAY_DIR"
    echo "$configJson" | jq '.' > "$CONFIG_FILE"
}

generateConfigHash() {
    if ! fileExists "$CONFIG_FILE"; then
        return
    fi
    
    jq -S '{
        outbounds: .outbounds,
        routing: .routing,
        inbounds: [.inbounds[] | del(.settings.clients)]
    }' "$CONFIG_FILE" 2>/dev/null | md5sum | awk '{print $1}'
}

saveConfigHash() {
    generateConfigHash > "$CONFIG_HASH_FILE"
}

checkConfigIntegrity() {
    if ! fileExists "$CONFIG_HASH_FILE" || ! fileExists "$CONFIG_FILE"; then
        return 0
    fi
    
    local saved=$(cat "$CONFIG_HASH_FILE" 2>/dev/null)
    local current=$(generateConfigHash)
    
    [ "$saved" = "$current" ]
}

userExists() {
    local email="$1"
    local result=$(jq -r --arg email "$email" \
        '.inbounds[0].settings.clients[] | select(.email == $email) | .email' \
        "$CONFIG_FILE" 2>/dev/null)
    [ -n "$result" ] && [ "$result" != "null" ]
}

getUserUuid() {
    local email="$1"
    jq -r --arg email "$email" \
        '.inbounds[0].settings.clients[] | select(.email == $email) | .id' \
        "$CONFIG_FILE" 2>/dev/null
}

getAllUsers() {
    jq -r '.inbounds[0].settings.clients[] | .email' "$CONFIG_FILE" 2>/dev/null
}

getAllUsersJson() {
    jq -c '.inbounds[0].settings.clients[]' "$CONFIG_FILE" 2>/dev/null
}

addUserToConfig() {
    local uuid="$1"
    local email="$2"
    local flow="${3:-xtls-rprx-vision}"
    
    local client=$(generateClient "$uuid" "$email" "$flow")
    
    safeJsonUpdate "$CONFIG_FILE" \
        --argjson client "$client" \
        '.inbounds[0].settings.clients += [$client]'
}

removeUserFromConfig() {
    local email="$1"
    
    safeJsonUpdate "$CONFIG_FILE" \
        --arg email "$email" \
        '.inbounds[0].settings.clients |= map(select(.email != $email))'
}

generateVlessLink() {
    local uuid="$1"
    local domain="$2"
    local email="$3"
    
    echo "vless://${uuid}@${domain}:443?security=tls&encryption=none&flow=xtls-rprx-vision&fp=chrome&type=tcp&sni=${domain}#${domain}-${email}"
}

generateSubLink() {
    local domain="$1"
    local subUri="$2"
    local email="$3"
    
    local filename=$(toBase64 "$email")
    echo "https://${domain}/${subUri}/${filename}"
}

createSubscriptionFile() {
    local email="$1"
    local uuid="$2"
    local domain="$3"
    
    local filename=$(toBase64 "$email")
    local vlessLink=$(generateVlessLink "$uuid" "$domain" "$email")
    
    mkdir -p "$SUBS_DIR"
    echo -n "$vlessLink" | base64 -w 0 > "$SUBS_DIR/$filename"
    chmod 644 "$SUBS_DIR/$filename"
}

deleteSubscriptionFile() {
    local email="$1"
    local filename=$(toBase64 "$email")
    rm -f "$SUBS_DIR/$filename"
}

regenerateAllSubscriptions() {
    local domain="${1:-$(getDomain)}"
    
    if ! fileExists "$CONFIG_FILE"; then
        logError "Config not found"
        return 1
    fi
    
    logInfo "Regenerating subscriptions for domain: $domain"
    
    rm -rf "$SUBS_DIR"/*
    mkdir -p "$SUBS_DIR"
    
    local count=0
    while IFS= read -r line; do
        local email=$(echo "$line" | jq -r '.email')
        local uuid=$(echo "$line" | jq -r '.id')
        
        if [ -n "$email" ] && [ "$email" != "null" ]; then
            createSubscriptionFile "$email" "$uuid" "$domain"
            echo -e "  ${GREEN}✓${NC} $email" >&2
            ((count++))
        fi
    done < <(getAllUsersJson)
    
    logSuccess "Updated: $count"
}

createBackup() {
    mkdir -p "$BACKUP_DIR"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backupPath="$BACKUP_DIR/$timestamp"
    mkdir -p "$backupPath"
    
    logInfo "Creating backup..."
    
    if fileExists "$CONFIG_FILE"; then
        jq '.inbounds[0].settings.clients' "$CONFIG_FILE" > "$backupPath/users.json" 2>/dev/null
        cp "$CONFIG_FILE" "$backupPath/config.json.bak"
    fi
    
    if dirExists "$SUBS_DIR" && [ "$(ls -A "$SUBS_DIR" 2>/dev/null)" ]; then
        cp -r "$SUBS_DIR" "$backupPath/subs_backup"
    fi
    
    if fileExists "$INFO_FILE"; then
        cp "$INFO_FILE" "$backupPath/install_info.txt.bak"
    fi
    
    echo "$backupPath" > "$BACKUP_DIR/latest"
    
    local userCount=$(jq 'length' "$backupPath/users.json" 2>/dev/null || echo 0)
    logSuccess "Users saved: $userCount"
    
    echo "$backupPath"
}

restoreUsersFromBackup() {
    local backupPath="$1"
    local currentAdmin="$2"
    local domain="$3"
    
    if ! fileExists "$backupPath/users.json"; then
        logInfo "Users backup not found"
        return 0
    fi
    
    local userCount=$(jq 'length' "$backupPath/users.json" 2>/dev/null || echo 0)
    if [ "$userCount" -eq 0 ]; then
        return 0
    fi
    
    logInfo "Restoring $userCount users..."
    
    local restored=0
    local skipped=0
    
    while IFS= read -r user; do
        local email=$(echo "$user" | jq -r '.email')
        local uuid=$(echo "$user" | jq -r '.id')
        local flow=$(echo "$user" | jq -r '.flow // "xtls-rprx-vision"')
        
        if [ -n "$currentAdmin" ] && [ "$email" = "$currentAdmin" ]; then
            ((skipped++))
            continue
        fi
        
        if [[ "$email" == admin_* ]]; then
            ((skipped++))
            continue
        fi
        
        if userExists "$email"; then
            ((skipped++))
            continue
        fi
        
        if addUserToConfig "$uuid" "$email" "$flow"; then
            ((restored++))
        fi
        
    done < <(jq -c '.[]' "$backupPath/users.json")
    
    logSuccess "Restored: $restored, Skipped: $skipped"
    
    if [ $restored -gt 0 ]; then
        regenerateAllSubscriptions "$domain"
    fi
}

listBackups() {
    echo ""
    echo -e "${CYAN}Available Backups:${NC}"
    echo "─────────────────────────────────────────"
    
    if ! dirExists "$BACKUP_DIR"; then
        echo -e "${GRAY}  No backups found${NC}"
        echo "─────────────────────────────────────────"
        return
    fi
    
    local i=1
    for dir in $(ls -1d "$BACKUP_DIR"/20* 2>/dev/null | sort -r | head -10); do
        local name=$(basename "$dir")
        local users=$(jq 'length' "$dir/users.json" 2>/dev/null || echo "?")
        echo -e "  $i. ${CYAN}$name${NC} | users: $users"
        ((i++))
    done
    
    if [ $i -eq 1 ]; then
        echo -e "${GRAY}  No backups found${NC}"
    fi
    
    echo "─────────────────────────────────────────"
}

getSystemArch() {
    case $(uname -m) in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "armv7" ;;
        *)       echo "" ;;
    esac
}

generateWarpKeys() {
    local arch=$(getSystemArch)
    
    if [ -z "$arch" ]; then
        logError "Arch not supported for WARP"
        return 1
    fi
    
    logInfo "Generating WARP keys..."
    
    pushd /tmp > /dev/null
    
    local version=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | jq -r '.tag_name' | tr -d 'v')
    version="${version:-2.2.22}"
    
    local url="https://github.com/ViRb3/wgcf/releases/download/v${version}/wgcf_${version}_linux_${arch}"
    
    if ! wget -qO wgcf "$url" || [ ! -s wgcf ]; then
        logError "Failed to download wgcf"
        popd > /dev/null
        return 1
    fi
    
    chmod +x wgcf
    ./wgcf register --accept-tos > /dev/null 2>&1
    ./wgcf generate > /dev/null 2>&1
    
    local result=""
    
    if fileExists wgcf-profile.conf; then
        local privateKey=$(grep "^PrivateKey" wgcf-profile.conf | cut -d'=' -f2 | tr -d ' ')
        local ipv4=$(grep "^Address" wgcf-profile.conf | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1)
        local ipv6=$(grep "^Address" wgcf-profile.conf | grep -oE '[0-9a-fA-F:]+:[0-9a-fA-F:]+/[0-9]+' | head -1)
        
        ipv4="${ipv4:-172.16.0.2/32}"
        
        local addresses="\"$ipv4\""
        if [ -n "$ipv6" ]; then
            addresses="\"$ipv4\", \"$ipv6\""
            logSuccess "WARP: IPv4 + IPv6"
        else
            logInfo "WARP: IPv4 only"
        fi
        
        result="${privateKey}|${addresses}"
    fi
    
    rm -f wgcf wgcf-account.toml wgcf-profile.conf
    popd > /dev/null
    
    echo "$result"
}

configureNginxAcme() {
    local domain="$1"
    
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null
    
    cat > /etc/nginx/conf.d/00-acme.conf <<EOF
server {
    listen 80;
    server_name $domain;
    root /var/www/html;

    location /.well-known/acme-challenge/ {
        allow all;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF
}

configureNginxFallback() {
    local domain="$1"
    local subUri="$2"
    
    cat > /etc/nginx/conf.d/fallback.conf <<EOF
server {
    listen 127.0.0.1:8080;
    server_name $domain;
    root /var/www/html;
    index index.html;
    
    location /$subUri/ {
        alias $SUBS_DIR/;
        default_type text/plain;
        autoindex off;
    }
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
}

obtainSslCertificate() {
    local domain="$1"
    local certPath="$CERT_BASE/$domain"
    
    if fileExists "$certPath/fullchain.pem"; then
        logInfo "Certificate already exists"
        return 0
    fi
    
    logInfo "Obtaining SSL certificate..."
    
    certbot certonly \
        --webroot \
        -w /var/www/html \
        -d "$domain" \
        --non-interactive \
        --agree-tos \
        -m "admin@$domain"
    
    if ! fileExists "$certPath/fullchain.pem"; then
        logError "Failed to obtain certificate"
        return 1
    fi
    
    logSuccess "SSL certificate obtained"
}

setupSslRenewalHook() {
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    
    cat > /etc/letsencrypt/renewal-hooks/deploy/01-restart-xray.sh <<'EOF'
#!/bin/bash
systemctl restart xray
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/01-restart-xray.sh
    
    if systemctl list-unit-files | grep -q certbot.timer; then
        systemctl enable --now certbot.timer > /dev/null 2>&1
    fi
}

getSslDaysLeft() {
    local domain="$1"
    local certPath="$CERT_BASE/$domain/fullchain.pem"
    
    if ! fileExists "$certPath"; then
        echo "-1"
        return
    fi
    
    local expiry=$(openssl x509 -enddate -noout -in "$certPath" 2>/dev/null | cut -d= -f2)
    if [ -z "$expiry" ]; then
        echo "-1"
        return
    fi
    
    local expiryEpoch=$(date -d "$expiry" +%s 2>/dev/null)
    local nowEpoch=$(date +%s)
    
    echo $(( (expiryEpoch - nowEpoch) / 86400 ))
}

installXrayBinary() {
    logInfo "Installing Xray..."
    
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install > /dev/null 2>&1
    
    sed -i 's/User=nobody/User=root/' /etc/systemd/system/xray.service
    sed -i '/^CapabilityBoundingSet/d' /etc/systemd/system/xray.service
    sed -i '/^AmbientCapabilities/d' /etc/systemd/system/xray.service
    
    systemctl daemon-reload
}

applySysctlTweaks() {
    cat > /etc/sysctl.d/99-xray-performance.conf <<EOF
fs.file-max = 1000000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.somaxconn = 65535
net.ipv4.tcp_keepalive_time = 600
EOF
    sysctl --system > /dev/null 2>&1
}

cmdListUsers() {
    if ! fileExists "$CONFIG_FILE"; then
        logError "Config not found"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}Users:${NC}"
    echo "─────────────────────────────"
    
    local users=$(getAllUsers)
    
    if [ -z "$users" ]; then
        echo -e "${GRAY}  No users${NC}"
    else
        local i=1
        while IFS= read -r user; do
            echo "  $i. $user"
            ((i++))
        done <<< "$users"
    fi
    
    echo "─────────────────────────────"
}

cmdAddUser() {
    local username="$1"
    local domain=$(getDomain)
    local subUri=$(getSubUri)
    
    if ! fileExists "$INFO_FILE"; then
        logError "Config not found"
        return 1
    fi
    
    if [ -z "$username" ]; then
        cmdListUsers
        read -p "New username: " username
    fi
    
    if [ -z "$username" ]; then
        logError "Username required"
        return 1
    fi
    
    if ! validateUsername "$username"; then
        logError "Invalid username (2-32 chars, letters, numbers, _, -)"
        return 1
    fi
    
    if userExists "$username"; then
        logError "User $username already exists"
        return 1
    fi
    
    local uuid=$(generateUuid)
    
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    if ! addUserToConfig "$uuid" "$username"; then
        logError "Failed to add user"
        return 1
    fi
    
    systemctl restart xray
    
    createSubscriptionFile "$username" "$uuid" "$domain"
    
    local subLink=$(generateSubLink "$domain" "$subUri" "$username")
    
    logSuccess "User $username added"
    
    echo ""
    echo -e "${YELLOW}Subscription link:${NC} $subLink"
    showQr "$subLink" "Subscription $username"
}

cmdShowUser() {
    local username="$1"
    local domain=$(getDomain)
    local subUri=$(getSubUri)
    
    if ! fileExists "$INFO_FILE"; then
        logError "Config not found"
        return 1
    fi
    
    if [ -z "$username" ]; then
        cmdListUsers
        read -p "Username: " username
    fi
    
    if [ -z "$username" ]; then
        return 0
    fi
    
    local uuid=$(getUserUuid "$username")
    
    if [ -z "$uuid" ] || [ "$uuid" = "null" ]; then
        logError "User $username not found"
        return 1
    fi
    
    local subLink=$(generateSubLink "$domain" "$subUri" "$username")
    local vlessLink=$(generateVlessLink "$uuid" "$domain" "$username")
    
    local filename=$(toBase64 "$username")
    if ! fileExists "$SUBS_DIR/$filename"; then
        createSubscriptionFile "$username" "$uuid" "$domain"
        logInfo "Subscription file restored"
    fi
    
    clear
    echo -e "${GREEN}User: $username${NC}"
    echo "─────────────────────────────────────────"
    echo -e "Subscription:"
    echo -e "${YELLOW}$subLink${NC}"
    showQr "$subLink" "Subscription"
    echo "─────────────────────────────────────────"
    echo -e "VLESS Key:"
    echo -e "${YELLOW}$vlessLink${NC}"
    showQr "$vlessLink" "VLESS"
}

cmdDeleteUser() {
    local username="$1"
    
    if ! fileExists "$INFO_FILE"; then
        logError "Config not found"
        return 1
    fi
    
    if [ -z "$username" ]; then
        cmdListUsers
        read -p "Username to delete: " username
    fi
    
    if [ -z "$username" ]; then
        return 0
    fi
    
    if ! userExists "$username"; then
        logError "User not found"
        return 1
    fi
    
    read -p "Delete $username? [y/n]: " confirm
    if [ "$confirm" != "y" ]; then
        echo "Cancelled"
        return 0
    fi
    
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    if ! removeUserFromConfig "$username"; then
        logError "Failed to delete"
        return 1
    fi
    
    systemctl restart xray
    deleteSubscriptionFile "$username"
    
    logSuccess "User $username deleted"
}

cmdHealthCheck() {
    echo ""
    logInfo "System Check..."
    echo ""
    echo "─────────────────────────────────────"
    
    local issues=0
    local domain=$(getDomain)
    
    if isServiceRunning xray; then
        echo -e "  Xray:        ${GREEN}✓ running${NC}"
    else
        echo -e "  Xray:        ${RED}✕ stopped${NC}"
        ((issues++))
    fi
    
    if isServiceRunning nginx; then
        echo -e "  Nginx:       ${GREEN}✓ running${NC}"
    else
        echo -e "  Nginx:       ${RED}✕ stopped${NC}"
        ((issues++))
    fi
    
    if ss -tlnp | grep -q ':443'; then
        echo -e "  Port 443:    ${GREEN}✓ open${NC}"
    else
        echo -e "  Port 443:    ${RED}✕ closed${NC}"
        ((issues++))
    fi
    
    local daysLeft=$(getSslDaysLeft "$domain")
    if [ "$daysLeft" -gt 30 ]; then
        echo -e "  SSL:         ${GREEN}✓ $daysLeft days${NC}"
    elif [ "$daysLeft" -gt 7 ]; then
        echo -e "  SSL:         ${YELLOW}⚠ $daysLeft days${NC}"
        ((issues++))
    elif [ "$daysLeft" -ge 0 ]; then
        echo -e "  SSL:         ${RED}✕ $daysLeft days!${NC}"
        ((issues++))
    else
        echo -e "  SSL:         ${RED}✕ not found${NC}"
        ((issues++))
    fi
    
    if isServiceRunning certbot.timer; then
        echo -e "  Auto-Renew:  ${GREEN}✓ active${NC}"
    else
        echo -e "  Auto-Renew:  ${YELLOW}⚠ inactive${NC}"
    fi
    
    if checkConfigIntegrity; then
        echo -e "  Config:      ${GREEN}✓ OK${NC}"
    else
        echo -e "  Config:      ${YELLOW}⚠ changed${NC}"
        ((issues++))
    fi
    
    echo -e "  Users:       ${CYAN}$(getUserCount)${NC}"
    
    echo "─────────────────────────────────────"
    echo ""
    
    if [ $issues -eq 0 ]; then
        logSuccess "All checks passed"
    else
        logError "Issues found: $issues"
    fi
}

cmdStatus() {
    echo ""
    logInfo "Service Status..."
    echo ""
    
    if isServiceRunning xray; then
        echo -e "  Xray:  ${GREEN}●${NC} running (v$(getXrayVersion))"
    else
        echo -e "  Xray:  ${RED}●${NC} stopped"
    fi
    
    if isServiceRunning nginx; then
        echo -e "  Nginx: ${GREEN}●${NC} running"
    else
        echo -e "  Nginx: ${RED}●${NC} stopped"
    fi
    
    echo ""
    echo "  Users: $(getUserCount)"
}

cmdRestart() {
    logInfo "Restarting services..."
    systemctl restart xray
    systemctl restart nginx
    sleep 1
    cmdStatus
}

cmdUpdateXray() {
    echo ""
    
    if ! isXrayInstalled; then
        logError "Xray not installed"
        return 1
    fi
    
    local current=$(getXrayVersion)
    local latest=$(getLatestXrayVersion)
    
    echo "  Current: $current"
    echo "  Latest:  $latest"
    echo ""
    
    if [ "$current" = "$latest" ]; then
        logSuccess "Already latest version"
        return 0
    fi
    
    read -p "Update? [y/n]: " confirm
    if [ "$confirm" != "y" ]; then
        return 0
    fi
    
    createBackup
    
    logInfo "Updating..."
    installXrayBinary
    
    systemctl restart xray
    
    logSuccess "Updated: $current → $(getXrayVersion)"
}

cmdRenewSsl() {
    logInfo "Forcing SSL renewal..."
    
    if ! commandExists certbot; then
        logError "Certbot not installed"
        return 1
    fi
    
    if certbot renew --force-renewal; then
        systemctl restart xray
        logSuccess "Certificate updated"
    else
        logError "Update failed"
    fi
}

cmdRegenerateSubs() {
    local domain=$(getDomain)
    local subUri=$(getSubUri)
    
    echo ""
    logWarning "Regenerating subscriptions"
    echo "Current domain: $domain"
    echo "Current path: /$subUri/"
    echo ""
    
    read -p "Change domain? [y/n]: " change
    
    if [ "$change" = "y" ]; then
        read -p "New domain [$domain]: " newDomain
        newDomain="${newDomain:-$domain}"
        
        read -p "New secret word [Enter to keep]: " newSeed
        if [ -n "$newSeed" ]; then
            subUri=$(toBase64 "$newSeed")
        fi
        
        setInstallInfo "domain" "$newDomain"
        setInstallInfo "subUri" "$subUri"
        
        configureNginxFallback "$newDomain" "$subUri"
        systemctl restart nginx
        
        domain="$newDomain"
    fi
    
    read -p "Continue? [y/n]: " confirm
    if [ "$confirm" != "y" ]; then
        return 0
    fi
    
    regenerateAllSubscriptions "$domain"
    
    logSuccess "Done! Links: https://$domain/$subUri/<user>"
}

cmdAcceptConfig() {
    echo ""
    logWarning "Accept current config as baseline?"
    echo "Script will stop warning about changes."
    echo ""
    
    read -p "Confirm? [y/n]: " confirm
    if [ "$confirm" = "y" ]; then
        saveConfigHash
        logSuccess "Changes accepted"
    fi
}

cmdInstall() {
    clear
    
    local savedBackup=""
    local oldDomain=""
    
    if isXrayInstalled; then
        echo -e "${YELLOW}Xray already installed${NC}"
        echo ""
        echo "  1. Reinstall (save users)"
        echo "  2. Clean install"
        echo "  0. Cancel"
        echo ""
        read -p "Choice: " choice
        
        case "$choice" in
            1)
                savedBackup=$(createBackup)
                oldDomain=$(getDomain)
                ;;
            2)
                read -p "Delete ALL users? [y/n]: " confirm
                [ "$confirm" != "y" ] && return 0
                ;;
            *)
                return 0
                ;;
        esac
        
        systemctl stop xray nginx 2>/dev/null
    fi
    
    echo -e "${GREEN}Installing Xray + WARP${NC}"
    echo ""
    
    if [ -n "$oldDomain" ]; then
        read -p "Domain [$oldDomain]: " domain
        domain="${domain:-$oldDomain}"
    else
        read -p "Domain: " domain
    fi
    
    if [ -z "$domain" ]; then
        logError "Domain required"
        return 1
    fi
    
    echo ""
    read -p "Secret word [sub]: " seedWord
    seedWord="${seedWord:-sub}"
    local subUri=$(toBase64 "$seedWord")
    logInfo "Subs path: /$subUri/"
    
    local adminUser="admin_$(generateRandomSuffix)"
    logInfo "Admin: $adminUser"
    
    logInfo "Installing packages..."
    apt update -q && apt upgrade -y -q
    apt install -y -q curl socat nginx certbot lsb-release jq qrencode
    
    rm -rf "$SUBS_DIR"
    mkdir -p "$SUBS_DIR" /var/www/html
    chmod 755 "$SUBS_DIR"
    chown www-data:www-data "$SUBS_DIR"
    
    applySysctlTweaks
    
    local warpResult=$(generateWarpKeys)
    local warpKey=""
    local warpAddresses=""
    
    if [ -n "$warpResult" ]; then
        warpKey=$(echo "$warpResult" | cut -d'|' -f1)
        warpAddresses=$(echo "$warpResult" | cut -d'|' -f2)
    fi
    
    configureNginxAcme "$domain"
    systemctl restart nginx
    
    if ! obtainSslCertificate "$domain"; then
        logError "Check DNS pointing to this server"
        return 1
    fi
    
    setupSslRenewalHook
    
    installXrayBinary
    
    local certPath="$CERT_BASE/$domain"
    local configJson=$(buildConfig "$certPath" "$warpKey" "$warpAddresses")
    saveConfig "$configJson"
    
    local adminUuid=$(generateUuid)
    addUserToConfig "$adminUuid" "$adminUser"
    
    configureNginxFallback "$domain" "$subUri"
    
    if [ ! -f "/var/www/html/index.html" ]; then
        echo "<h1>Welcome</h1>" > /var/www/html/index.html
    fi
    
    setInstallInfo "domain" "$domain"
    setInstallInfo "subUri" "$subUri"
    
    createSubscriptionFile "$adminUser" "$adminUuid" "$domain"
    
    if [ -n "$savedBackup" ]; then
        restoreUsersFromBackup "$savedBackup" "$adminUser" "$domain"
    fi
    
    saveConfigHash
    
    systemctl restart nginx xray
    systemctl enable xray nginx > /dev/null 2>&1
    
    sleep 2
    
    if isServiceRunning xray; then
        logSuccess "Xray started!"
    else
        logError "Xray failed start: journalctl -u xray -n 50"
    fi
    
    echo ""
    logSuccess "Installation complete"
    echo ""
    echo "  Users: $(getUserCount)"
    echo "  Admin: $adminUser"
    echo ""
    
    local subLink=$(generateSubLink "$domain" "$subUri" "$adminUser")
    echo -e "  Subscription: ${YELLOW}$subLink${NC}"
    showQr "$subLink" "Subscription $adminUser"
}

cmdUninstall() {
    echo ""
    echo -e "${RED}Uninstalling Xray${NC}"
    echo ""
    echo "  1. Uninstall (save backup)"
    echo "  2. Uninstall completely"
    echo "  0. Cancel"
    echo ""
    read -p "Choice: " choice
    
    case "$choice" in
        1)
            createBackup
            logSuccess "Backup saved to $BACKUP_DIR"
            ;;
        2)
            read -p "Delete EVERYTHING including backups? [y/n]: " confirm
            [ "$confirm" != "y" ] && return 0
            rm -rf "$BACKUP_DIR"
            ;;
        *)
            return 0
            ;;
    esac
    
    logInfo "Stopping services..."
    systemctl stop xray
    systemctl disable xray > /dev/null 2>&1
    
    logInfo "Removing files..."
    rm -rf /usr/local/bin/xray
    rm -rf "$XRAY_DIR"
    rm -rf /usr/local/share/xray
    rm -rf "$SUBS_DIR"
    rm -f /etc/systemd/system/xray.service
    rm -rf /etc/systemd/system/xray.service.d
    rm -f /etc/nginx/conf.d/fallback.conf
    rm -f /etc/nginx/conf.d/00-acme.conf
    rm -f /etc/sysctl.d/99-xray-performance.conf
    rm -f /etc/letsencrypt/renewal-hooks/deploy/01-restart-xray.sh
    
    systemctl daemon-reload
    systemctl restart nginx
    
    logSuccess "Uninstalled"
    
    if dirExists "$BACKUP_DIR"; then
        echo -e "${YELLOW}Backups: $BACKUP_DIR${NC}"
    fi
}

cmdRestoreBackup() {
    listBackups
    
    if ! dirExists "$BACKUP_DIR"; then
        return 0
    fi
    
    echo ""
    read -p "Backup name: " backupName
    
    if [ -z "$backupName" ]; then
        return 0
    fi
    
    local backupPath="$BACKUP_DIR/$backupName"
    
    if ! dirExists "$backupPath"; then
        logError "Backup not found"
        return 1
    fi
    
    if ! fileExists "$INFO_FILE"; then
        logError "Install Xray first"
        return 1
    fi
    
    read -p "Restore from $backupName? [y/n]: " confirm
    [ "$confirm" != "y" ] && return 0
    
    restoreUsersFromBackup "$backupPath" "" "$(getDomain)"
    systemctl restart xray
    
    logSuccess "Restored"
}

showMenu() {
    while true; do
        clear
        
        local configChanged=false
        checkConfigIntegrity || configChanged=true
        
        echo -e "${CYAN}═══════════════════════════════════════${NC}"
        echo -e "${CYAN}          XRAY MANAGER v${VERSION}${NC}"
        echo -e "${CYAN}═══════════════════════════════════════${NC}"
        
        local status=$(getStatus)
        
        case $status in
            running)
                echo -e "  Status: ${GREEN}● Running${NC}"
                echo -e "  Domain: $(getDomain)"
                echo -e "  Users:  $(getUserCount)"
                ;;
            stopped)
                echo -e "  Status: ${RED}● Stopped${NC}"
                echo -e "  Domain: $(getDomain)"
                ;;
            not_installed)
                echo -e "  Status: ${GRAY}○ Not Installed${NC}"
                ;;
        esac
        
        if [ "$configChanged" = true ]; then
            echo -e "  ${RED}⚠ Config changed!${NC}"
        fi
        
        echo -e "${CYAN}───────────────────────────────────────${NC}"
        
        if [ "$status" != "not_installed" ]; then
            echo -e "${YELLOW} Users${NC}"
            echo "  1. List"
            echo "  2. Add"
            echo "  3. Show"
            echo "  4. Delete"
            echo ""
            echo -e "${YELLOW} System${NC}"
            echo "  5. Health Check"
            echo "  6. Restart"
            echo "  7. Update Xray"
            echo "  8. Renew SSL"
            echo ""
            echo -e "${YELLOW} Subscriptions${NC}"
            echo "  9. Regenerate All"
            echo "  10. Backups"
            echo "  11. Restore"
            
            if [ "$configChanged" = true ]; then
                echo ""
                echo -e "${RED} Config${NC}"
                echo "  12. Accept Changes"
            fi
            
            echo ""
            echo -e "${GRAY}  20. Reinstall${NC}"
            echo -e "${GRAY}  21. Uninstall${NC}"
        else
            echo ""
            echo "  1. Install"
            
            if dirExists "$BACKUP_DIR" && [ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
                echo -e "${YELLOW}  2. Show Backups${NC}"
            fi
        fi
        
        echo ""
        echo "  0. Exit"
        echo -e "${CYAN}───────────────────────────────────────${NC}"
        read -p "  > " choice
        
        if [ "$status" = "not_installed" ]; then
            case "$choice" in
                1) cmdInstall; read -p "Enter..." ;;
                2) listBackups; read -p "Enter..." ;;
                0) exit 0 ;;
            esac
        else
            case "$choice" in
                1)  cmdListUsers; read -p "Enter..." ;;
                2)  cmdAddUser; read -p "Enter..." ;;
                3)  cmdShowUser; read -p "Enter..." ;;
                4)  cmdDeleteUser; read -p "Enter..." ;;
                5)  cmdHealthCheck; read -p "Enter..." ;;
                6)  cmdRestart; read -p "Enter..." ;;
                7)  cmdUpdateXray; read -p "Enter..." ;;
                8)  cmdRenewSsl; read -p "Enter..." ;;
                9)  cmdRegenerateSubs; read -p "Enter..." ;;
                10) listBackups; read -p "Enter..." ;;
                11) cmdRestoreBackup; read -p "Enter..." ;;
                12) cmdAcceptConfig; read -p "Enter..." ;;
                20) cmdInstall; read -p "Enter..." ;;
                21) cmdUninstall; read -p "Enter..." ;;
                0)  exit 0 ;;
            esac
        fi
    done
}

showHelp() {
    cat <<EOF
Xray Manager v$VERSION

Usage: $0 [command] [args]

Users:
  list              List users
  add <name>        Add user
  show <name>       Show details
  del <name>        Delete user

System:
  install           Install
  health            System check
  status            Service status
  restart           Restart services
  update            Update Xray
  renew             Renew SSL

Subs:
  regen             Regenerate all
  backup            Create backup
  backups           List backups
  restore           Restore backup

Misc:
  accept-config     Accept config changes
  remove            Uninstall
  help              Help
EOF
}

requireRoot

if [ "$(getStatus)" != "not_installed" ]; then
    for cmd in jq curl; do
        if ! commandExists "$cmd"; then
            apt update -q && apt install -y "$cmd"
        fi
    done
fi

if [ $# -eq 0 ]; then
    showMenu
else
    case "$1" in
        install)        cmdInstall ;;
        list)           cmdListUsers ;;
        add)            cmdAddUser "$2" ;;
        show)           cmdShowUser "$2" ;;
        del)            cmdDeleteUser "$2" ;;
        health)         cmdHealthCheck ;;
        status)         cmdStatus ;;
        restart)        cmdRestart ;;
        update)         cmdUpdateXray ;;
        renew)          cmdRenewSsl ;;
        regen)          cmdRegenerateSubs ;;
        backup)         createBackup ;;
        backups)        listBackups ;;
        restore)        cmdRestoreBackup ;;
        accept-config)  cmdAcceptConfig ;;
        remove)         cmdUninstall ;;
        help|-h|--help) showHelp ;;
        *)              showHelp; exit 1 ;;
    esac
fi
