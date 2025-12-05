#!/bin/bash

# ============================================================
# КОНСТАНТЫ И ПУТИ
# ============================================================

readonly XRAY_DIR="/usr/local/etc/xray"
readonly INFO_FILE="$XRAY_DIR/install_info.txt"
readonly CONFIG_FILE="$XRAY_DIR/config.json"
readonly CONFIG_HASH_FILE="$XRAY_DIR/.config_hash"
readonly BACKUP_DIR="$XRAY_DIR/backup"
readonly SUBS_DIR="/var/www/html/subs"
readonly CERT_BASE="/etc/letsencrypt/live"

readonly VERSION="3.0"

# ============================================================
# ЦВЕТА
# ============================================================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly GRAY='\033[0;90m'
readonly NC='\033[0m'

# ============================================================
# ЛОГИРОВАНИЕ
# ============================================================

log_info()    { echo -e "${YELLOW}• $1${NC}"; }
log_success() { echo -e "${GREEN}✓ $1${NC}"; }
log_error()   { echo -e "${RED}✕ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }

# ============================================================
# УТИЛИТЫ
# ============================================================

require_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Запустите скрипт с правами root."
        exit 1
    fi
}

to_base64() {
    echo -n "$1" | base64 | tr '+/' '-_' | tr -d '='
}

generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

generate_random_suffix() {
    head /dev/urandom | tr -dc 'a-z0-9' | head -c 5
}

validate_username() {
    local name="$1"
    [[ "$name" =~ ^[a-zA-Z0-9_-]{2,32}$ ]]
}

validate_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]
}

command_exists() {
    command -v "$1" &>/dev/null
}

file_exists() {
    [ -f "$1" ]
}

dir_exists() {
    [ -d "$1" ]
}

show_qr() {
    local data="$1"
    local label="$2"
    echo ""
    echo -e "${YELLOW}QR: $label${NC}"
    if command_exists qrencode; then
        qrencode -t ANSIUTF8 "$data"
    else
        log_warning "qrencode не установлен"
    fi
    echo ""
}

# Безопасное обновление JSON файла
safe_json_update() {
    local file="$1"
    local jq_filter="$2"
    shift 2
    
    local tmpfile=$(mktemp)
    if jq "$jq_filter" "$@" "$file" > "$tmpfile" && [ -s "$tmpfile" ]; then
        mv "$tmpfile" "$file"
        return 0
    else
        rm -f "$tmpfile"
        return 1
    fi
}

# ============================================================
# МОДУЛЬ: ИНФОРМАЦИЯ О СИСТЕМЕ
# ============================================================

get_install_info() {
    local key="$1"
    if file_exists "$INFO_FILE"; then
        grep "^${key}=" "$INFO_FILE" 2>/dev/null | cut -d'=' -f2
    fi
}

set_install_info() {
    local key="$1"
    local value="$2"
    
    mkdir -p "$XRAY_DIR"
    
    if file_exists "$INFO_FILE" && grep -q "^${key}=" "$INFO_FILE"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$INFO_FILE"
    else
        echo "${key}=${value}" >> "$INFO_FILE"
    fi
}

get_domain() {
    get_install_info "domain" || echo "-"
}

get_sub_uri() {
    get_install_info "subUri"
}

get_cert_path() {
    echo "$CERT_BASE/$(get_domain)"
}

# ============================================================
# МОДУЛЬ: СТАТУС СИСТЕМЫ
# ============================================================

is_xray_installed() {
    file_exists "/usr/local/bin/xray"
}

is_service_running() {
    systemctl is-active --quiet "$1"
}

get_status() {
    if ! is_xray_installed; then
        echo "not_installed"
    elif is_service_running xray; then
        echo "running"
    else
        echo "stopped"
    fi
}

get_user_count() {
    if file_exists "$CONFIG_FILE"; then
        jq -r '.inbounds[0].settings.clients | length' "$CONFIG_FILE" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

get_xray_version() {
    /usr/local/bin/xray version 2>/dev/null | head -n1 | awk '{print $2}'
}

get_latest_xray_version() {
    curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name' | tr -d 'v'
}

# ============================================================
# МОДУЛЬ: КОНФИГУРАЦИЯ XRAY (ЦЕНТРАЛИЗОВАННО!)
# ============================================================

# --- Генерация inbound ---
generate_inbound() {
    local port="$1"
    local cert_path="$2"
    
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
        "certificateFile": "$cert_path/fullchain.pem",
        "keyFile": "$cert_path/privkey.pem"
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

# --- Генерация клиента ---
generate_client() {
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

# --- Генерация outbound: WARP ---
generate_outbound_warp() {
    local private_key="$1"
    local addresses="$2"  # JSON array: "ip1", "ip2"
    
    cat <<EOF
{
  "tag": "warp",
  "protocol": "wireguard",
  "settings": {
    "secretKey": "$private_key",
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

# --- Генерация outbound: Direct ---
generate_outbound_direct() {
    echo '{ "tag": "direct", "protocol": "freedom" }'
}

# --- Генерация outbound: Block ---
generate_outbound_block() {
    echo '{ "tag": "block", "protocol": "blackhole" }'
}

# --- Генерация routing ---
generate_routing() {
    cat <<EOF
{
  "domainStrategy": "IPIfNonMatch",
  "rules": [
    { "type": "field", "outboundTag": "block", "ip": ["geoip:private"] }
  ]
}
EOF
}

# --- ГЛАВНАЯ ФУНКЦИЯ: Сборка полного конфига ---
build_config() {
    local cert_path="$1"
    local warp_key="$2"
    local warp_addresses="$3"
    
    local inbound=$(generate_inbound 443 "$cert_path")
    local routing=$(generate_routing)
    
    local outbounds
    if [ -n "$warp_key" ]; then
        local warp=$(generate_outbound_warp "$warp_key" "$warp_addresses")
        local direct=$(generate_outbound_direct)
        local block=$(generate_outbound_block)
        outbounds="[$warp, $block, $direct]"
    else
        local direct=$(generate_outbound_direct)
        local block=$(generate_outbound_block)
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

# --- Сохранение конфига ---
save_config() {
    local config_json="$1"
    mkdir -p "$XRAY_DIR"
    echo "$config_json" | jq '.' > "$CONFIG_FILE"
}

# --- Хеш конфига (для детекта изменений) ---
generate_config_hash() {
    if ! file_exists "$CONFIG_FILE"; then
        return
    fi
    
    jq -S '{
        outbounds: .outbounds,
        routing: .routing,
        inbounds: [.inbounds[] | del(.settings.clients)]
    }' "$CONFIG_FILE" 2>/dev/null | md5sum | awk '{print $1}'
}

save_config_hash() {
    generate_config_hash > "$CONFIG_HASH_FILE"
}

check_config_integrity() {
    if ! file_exists "$CONFIG_HASH_FILE" || ! file_exists "$CONFIG_FILE"; then
        return 0
    fi
    
    local saved=$(cat "$CONFIG_HASH_FILE" 2>/dev/null)
    local current=$(generate_config_hash)
    
    [ "$saved" = "$current" ]
}

# ============================================================
# МОДУЛЬ: УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# ============================================================

user_exists() {
    local email="$1"
    local result=$(jq -r --arg email "$email" \
        '.inbounds[0].settings.clients[] | select(.email == $email) | .email' \
        "$CONFIG_FILE" 2>/dev/null)
    [ -n "$result" ] && [ "$result" != "null" ]
}

get_user_uuid() {
    local email="$1"
    jq -r --arg email "$email" \
        '.inbounds[0].settings.clients[] | select(.email == $email) | .id' \
        "$CONFIG_FILE" 2>/dev/null
}

get_all_users() {
    jq -r '.inbounds[0].settings.clients[] | .email' "$CONFIG_FILE" 2>/dev/null
}

get_all_users_json() {
    jq -c '.inbounds[0].settings.clients[]' "$CONFIG_FILE" 2>/dev/null
}

add_user_to_config() {
    local uuid="$1"
    local email="$2"
    local flow="${3:-xtls-rprx-vision}"
    
    local client=$(generate_client "$uuid" "$email" "$flow")
    
    safe_json_update "$CONFIG_FILE" \
        --argjson client "$client" \
        '.inbounds[0].settings.clients += [$client]'
}

remove_user_from_config() {
    local email="$1"
    
    safe_json_update "$CONFIG_FILE" \
        --arg email "$email" \
        '.inbounds[0].settings.clients |= map(select(.email != $email))'
}

# ============================================================
# МОДУЛЬ: ПОДПИСКИ
# ============================================================

# Генерация VLESS ссылки (единая точка!)
generate_vless_link() {
    local uuid="$1"
    local domain="$2"
    local email="$3"
    
    echo "vless://${uuid}@${domain}:443?security=tls&encryption=none&flow=xtls-rprx-vision&fp=chrome&type=tcp&sni=${domain}#${domain}-${email}"
}

# Генерация ссылки на подписку
generate_sub_link() {
    local domain="$1"
    local sub_uri="$2"
    local email="$3"
    
    local filename=$(to_base64 "$email")
    echo "https://${domain}/${sub_uri}/${filename}"
}

# Создание файла подписки для пользователя
create_subscription_file() {
    local email="$1"
    local uuid="$2"
    local domain="$3"
    
    local filename=$(to_base64 "$email")
    local vless_link=$(generate_vless_link "$uuid" "$domain" "$email")
    
    mkdir -p "$SUBS_DIR"
    echo -n "$vless_link" | base64 -w 0 > "$SUBS_DIR/$filename"
    chmod 644 "$SUBS_DIR/$filename"
}

# Удаление файла подписки
delete_subscription_file() {
    local email="$1"
    local filename=$(to_base64 "$email")
    rm -f "$SUBS_DIR/$filename"
}

# Перегенерация всех подписок
regenerate_all_subscriptions() {
    local domain="${1:-$(get_domain)}"
    
    if ! file_exists "$CONFIG_FILE"; then
        log_error "Конфиг не найден"
        return 1
    fi
    
    log_info "Перегенерация подписок для домена: $domain"
    
    rm -rf "$SUBS_DIR"/*
    mkdir -p "$SUBS_DIR"
    
    local count=0
    while IFS= read -r line; do
        local email=$(echo "$line" | jq -r '.email')
        local uuid=$(echo "$line" | jq -r '.id')
        
        if [ -n "$email" ] && [ "$email" != "null" ]; then
            create_subscription_file "$email" "$uuid" "$domain"
            echo -e "  ${GREEN}✓${NC} $email"
            ((count++))
        fi
    done < <(get_all_users_json)
    
    log_success "Обновлено: $count"
}

# ============================================================
# МОДУЛЬ: БЭКАПЫ
# ============================================================

create_backup() {
    mkdir -p "$BACKUP_DIR"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_path="$BACKUP_DIR/$timestamp"
    mkdir -p "$backup_path"
    
    log_info "Создание бэкапа..."
    
    if file_exists "$CONFIG_FILE"; then
        jq '.inbounds[0].settings.clients' "$CONFIG_FILE" > "$backup_path/users.json" 2>/dev/null
        cp "$CONFIG_FILE" "$backup_path/config.json.bak"
    fi
    
    if dir_exists "$SUBS_DIR" && [ "$(ls -A "$SUBS_DIR" 2>/dev/null)" ]; then
        cp -r "$SUBS_DIR" "$backup_path/subs_backup"
    fi
    
    if file_exists "$INFO_FILE"; then
        cp "$INFO_FILE" "$backup_path/install_info.txt.bak"
    fi
    
    echo "$backup_path" > "$BACKUP_DIR/latest"
    
    local user_count=$(jq 'length' "$backup_path/users.json" 2>/dev/null || echo 0)
    log_success "Сохранено пользователей: $user_count"
    
    echo "$backup_path"
}

restore_users_from_backup() {
    local backup_path="$1"
    local skip_admin="$2"
    local domain="$3"
    
    if ! file_exists "$backup_path/users.json"; then
        log_info "Бэкап пользователей не найден"
        return 0
    fi
    
    local user_count=$(jq 'length' "$backup_path/users.json" 2>/dev/null || echo 0)
    if [ "$user_count" -eq 0 ]; then
        return 0
    fi
    
    log_info "Восстановление $user_count пользователей..."
    
    local restored=0
    local skipped=0
    
    while IFS= read -r user; do
        local email=$(echo "$user" | jq -r '.email')
        local uuid=$(echo "$user" | jq -r '.id')
        local flow=$(echo "$user" | jq -r '.flow // "xtls-rprx-vision"')
        
        # Пропуск нового админа
        if [ -n "$skip_admin" ] && [ "$email" = "$skip_admin" ]; then
            ((skipped++))
            continue
        fi
        
        # Пропуск существующих
        if user_exists "$email"; then
            ((skipped++))
            continue
        fi
        
        if add_user_to_config "$uuid" "$email" "$flow"; then
            ((restored++))
        fi
        
    done < <(jq -c '.[]' "$backup_path/users.json")
    
    log_success "Восстановлено: $restored, пропущено: $skipped"
    
    # Перегенерация подписок
    if [ $restored -gt 0 ]; then
        regenerate_all_subscriptions "$domain"
    fi
}

list_backups() {
    echo ""
    echo -e "${CYAN}Доступные бэкапы:${NC}"
    echo "─────────────────────────────────────────"
    
    if ! dir_exists "$BACKUP_DIR"; then
        echo -e "${GRAY}  Бэкапы отсутствуют${NC}"
        echo "─────────────────────────────────────────"
        return
    fi
    
    local i=1
    for dir in $(ls -1d "$BACKUP_DIR"/20* 2>/dev/null | sort -r | head -10); do
        local name=$(basename "$dir")
        local users=$(jq 'length' "$dir/users.json" 2>/dev/null || echo "?")
        echo -e "  $i. ${CYAN}$name${NC} | пользователей: $users"
        ((i++))
    done
    
    if [ $i -eq 1 ]; then
        echo -e "${GRAY}  Бэкапы отсутствуют${NC}"
    fi
    
    echo "─────────────────────────────────────────"
}

# ============================================================
# МОДУЛЬ: WARP
# ============================================================

get_system_arch() {
    case $(uname -m) in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "armv7" ;;
        *)       echo "" ;;
    esac
}

generate_warp_keys() {
    local arch=$(get_system_arch)
    
    if [ -z "$arch" ]; then
        log_error "Архитектура не поддерживается для WARP"
        return 1
    fi
    
    log_info "Генерация ключей WARP..."
    
    pushd /tmp > /dev/null
    
    local version=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | jq -r '.tag_name' | tr -d 'v')
    version="${version:-2.2.22}"
    
    local url="https://github.com/ViRb3/wgcf/releases/download/v${version}/wgcf_${version}_linux_${arch}"
    
    if ! wget -qO wgcf "$url" || [ ! -s wgcf ]; then
        log_error "Не удалось скачать wgcf"
        popd > /dev/null
        return 1
    fi
    
    chmod +x wgcf
    ./wgcf register --accept-tos > /dev/null 2>&1
    ./wgcf generate > /dev/null 2>&1
    
    local result=""
    
    if file_exists wgcf-profile.conf; then
        local private_key=$(grep "^PrivateKey" wgcf-profile.conf | cut -d'=' -f2 | tr -d ' ')
        local ipv4=$(grep "^Address" wgcf-profile.conf | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1)
        local ipv6=$(grep "^Address" wgcf-profile.conf | grep -oE '[0-9a-fA-F:]+:[0-9a-fA-F:]+/[0-9]+' | head -1)
        
        ipv4="${ipv4:-172.16.0.2/32}"
        
        local addresses="\"$ipv4\""
        if [ -n "$ipv6" ]; then
            addresses="\"$ipv4\", \"$ipv6\""
            log_success "WARP: IPv4 + IPv6"
        else
            log_info "WARP: только IPv4"
        fi
        
        result="${private_key}|${addresses}"
    fi
    
    rm -f wgcf wgcf-account.toml wgcf-profile.conf
    popd > /dev/null
    
    echo "$result"
}

# ============================================================
# МОДУЛЬ: NGINX
# ============================================================

configure_nginx_acme() {
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

configure_nginx_fallback() {
    local domain="$1"
    local sub_uri="$2"
    
    cat > /etc/nginx/conf.d/fallback.conf <<EOF
server {
    listen 127.0.0.1:8080;
    server_name $domain;
    root /var/www/html;
    index index.html;
    
    location /$sub_uri/ {
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

# ============================================================
# МОДУЛЬ: SSL
# ============================================================

obtain_ssl_certificate() {
    local domain="$1"
    local cert_path="$CERT_BASE/$domain"
    
    if file_exists "$cert_path/fullchain.pem"; then
        log_info "Сертификат уже существует"
        return 0
    fi
    
    log_info "Получение SSL сертификата..."
    
    certbot certonly \
        --webroot \
        -w /var/www/html \
        -d "$domain" \
        --non-interactive \
        --agree-tos \
        -m "admin@$domain"
    
    if ! file_exists "$cert_path/fullchain.pem"; then
        log_error "Ошибка получения сертификата"
        return 1
    fi
    
    log_success "SSL сертификат получен"
}

setup_ssl_renewal_hook() {
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

get_ssl_days_left() {
    local domain="$1"
    local cert_path="$CERT_BASE/$domain/fullchain.pem"
    
    if ! file_exists "$cert_path"; then
        echo "-1"
        return
    fi
    
    local expiry=$(openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null | cut -d= -f2)
    if [ -z "$expiry" ]; then
        echo "-1"
        return
    fi
    
    local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null)
    local now_epoch=$(date +%s)
    
    echo $(( (expiry_epoch - now_epoch) / 86400 ))
}

# ============================================================
# МОДУЛЬ: УСТАНОВКА XRAY
# ============================================================

install_xray_binary() {
    log_info "Установка Xray..."
    
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install > /dev/null 2>&1
    
    # Патч systemd unit
    sed -i 's/User=nobody/User=root/' /etc/systemd/system/xray.service
    sed -i '/^CapabilityBoundingSet/d' /etc/systemd/system/xray.service
    sed -i '/^AmbientCapabilities/d' /etc/systemd/system/xray.service
    
    systemctl daemon-reload
}

apply_sysctl_tweaks() {
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

# ============================================================
# КОМАНДЫ: ПОЛЬЗОВАТЕЛИ
# ============================================================

cmd_list_users() {
    if ! file_exists "$CONFIG_FILE"; then
        log_error "Конфигурация не найдена"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}Пользователи:${NC}"
    echo "─────────────────────────────"
    
    local users=$(get_all_users)
    
    if [ -z "$users" ]; then
        echo -e "${GRAY}  Нет пользователей${NC}"
    else
        local i=1
        while IFS= read -r user; do
            echo "  $i. $user"
            ((i++))
        done <<< "$users"
    fi
    
    echo "─────────────────────────────"
}

cmd_add_user() {
    local username="$1"
    local domain=$(get_domain)
    local sub_uri=$(get_sub_uri)
    
    if ! file_exists "$INFO_FILE"; then
        log_error "Конфигурация не найдена"
        return 1
    fi
    
    if [ -z "$username" ]; then
        cmd_list_users
        read -p "Имя нового пользователя: " username
    fi
    
    if [ -z "$username" ]; then
        log_error "Имя обязательно"
        return 1
    fi
    
    if ! validate_username "$username"; then
        log_error "Имя может содержать только буквы, цифры, _ и - (2-32 символа)"
        return 1
    fi
    
    if user_exists "$username"; then
        log_error "Пользователь $username уже существует"
        return 1
    fi
    
    local uuid=$(generate_uuid)
    
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    if ! add_user_to_config "$uuid" "$username"; then
        log_error "Ошибка добавления пользователя"
        return 1
    fi
    
    systemctl restart xray
    
    create_subscription_file "$username" "$uuid" "$domain"
    
    local sub_link=$(generate_sub_link "$domain" "$sub_uri" "$username")
    local vless_link=$(generate_vless_link "$uuid" "$domain" "$username")
    
    log_success "Пользователь $username добавлен"
    
    echo ""
    echo -e "${YELLOW}Ссылка подписки:${NC} $sub_link"
    show_qr "$sub_link" "Подписка $username"
}

cmd_show_user() {
    local username="$1"
    local domain=$(get_domain)
    local sub_uri=$(get_sub_uri)
    
    if ! file_exists "$INFO_FILE"; then
        log_error "Конфигурация не найдена"
        return 1
    fi
    
    if [ -z "$username" ]; then
        cmd_list_users
        read -p "Имя пользователя: " username
    fi
    
    if [ -z "$username" ]; then
        return 0
    fi
    
    local uuid=$(get_user_uuid "$username")
    
    if [ -z "$uuid" ] || [ "$uuid" = "null" ]; then
        log_error "Пользователь $username не найден"
        return 1
    fi
    
    local sub_link=$(generate_sub_link "$domain" "$sub_uri" "$username")
    local vless_link=$(generate_vless_link "$uuid" "$domain" "$username")
    
    # Восстановление файла подписки если нужно
    local filename=$(to_base64 "$username")
    if ! file_exists "$SUBS_DIR/$filename"; then
        create_subscription_file "$username" "$uuid" "$domain"
        log_info "Файл подписки восстановлен"
    fi
    
    clear
    echo -e "${GREEN}Пользователь: $username${NC}"
    echo "─────────────────────────────────────────"
    echo -e "Ссылка подписки:"
    echo -e "${YELLOW}$sub_link${NC}"
    show_qr "$sub_link" "Подписка"
    echo "─────────────────────────────────────────"
    echo -e "Ключ VLESS:"
    echo -e "${YELLOW}$vless_link${NC}"
    show_qr "$vless_link" "VLESS"
}

cmd_delete_user() {
    local username="$1"
    
    if ! file_exists "$INFO_FILE"; then
        log_error "Конфигурация не найдена"
        return 1
    fi
    
    if [ -z "$username" ]; then
        cmd_list_users
        read -p "Имя для удаления: " username
    fi
    
    if [ -z "$username" ]; then
        return 0
    fi
    
    if ! user_exists "$username"; then
        log_error "Пользователь не найден"
        return 1
    fi
    
    read -p "Удалить $username? [y/n]: " confirm
    if [ "$confirm" != "y" ]; then
        echo "Отменено"
        return 0
    fi
    
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    if ! remove_user_from_config "$username"; then
        log_error "Ошибка удаления"
        return 1
    fi
    
    systemctl restart xray
    delete_subscription_file "$username"
    
    log_success "Пользователь $username удалён"
}

# ============================================================
# КОМАНДЫ: СИСТЕМА
# ============================================================

cmd_health_check() {
    echo ""
    log_info "Проверка системы..."
    echo ""
    echo "─────────────────────────────────────"
    
    local issues=0
    local domain=$(get_domain)
    
    # Xray
    if is_service_running xray; then
        echo -e "  Xray:        ${GREEN}✓ работает${NC}"
    else
        echo -e "  Xray:        ${RED}✕ остановлен${NC}"
        ((issues++))
    fi
    
    # Nginx
    if is_service_running nginx; then
        echo -e "  Nginx:       ${GREEN}✓ работает${NC}"
    else
        echo -e "  Nginx:       ${RED}✕ остановлен${NC}"
        ((issues++))
    fi
    
    # Порт 443
    if ss -tlnp | grep -q ':443'; then
        echo -e "  Порт 443:    ${GREEN}✓ открыт${NC}"
    else
        echo -e "  Порт 443:    ${RED}✕ закрыт${NC}"
        ((issues++))
    fi
    
    # SSL
    local days_left=$(get_ssl_days_left "$domain")
    if [ "$days_left" -gt 30 ]; then
        echo -e "  SSL:         ${GREEN}✓ $days_left дней${NC}"
    elif [ "$days_left" -gt 7 ]; then
        echo -e "  SSL:         ${YELLOW}⚠ $days_left дней${NC}"
        ((issues++))
    elif [ "$days_left" -ge 0 ]; then
        echo -e "  SSL:         ${RED}✕ $days_left дней!${NC}"
        ((issues++))
    else
        echo -e "  SSL:         ${RED}✕ не найден${NC}"
        ((issues++))
    fi
    
    # Certbot timer
    if is_service_running certbot.timer; then
        echo -e "  Auto-Renew:  ${GREEN}✓ активен${NC}"
    else
        echo -e "  Auto-Renew:  ${YELLOW}⚠ не запущен${NC}"
    fi
    
    # Целостность конфига
    if check_config_integrity; then
        echo -e "  Конфиг:      ${GREEN}✓ OK${NC}"
    else
        echo -e "  Конфиг:      ${YELLOW}⚠ изменён${NC}"
        ((issues++))
    fi
    
    # Пользователи
    echo -e "  Users:       ${CYAN}$(get_user_count)${NC}"
    
    echo "─────────────────────────────────────"
    echo ""
    
    if [ $issues -eq 0 ]; then
        log_success "Все проверки пройдены"
    else
        log_error "Проблем: $issues"
    fi
}

cmd_status() {
    echo ""
    log_info "Статус сервисов..."
    echo ""
    
    if is_service_running xray; then
        echo -e "  Xray:  ${GREEN}●${NC} работает (v$(get_xray_version))"
    else
        echo -e "  Xray:  ${RED}●${NC} остановлен"
    fi
    
    if is_service_running nginx; then
        echo -e "  Nginx: ${GREEN}●${NC} работает"
    else
        echo -e "  Nginx: ${RED}●${NC} остановлен"
    fi
    
    echo ""
    echo "  Пользователей: $(get_user_count)"
}

cmd_restart() {
    log_info "Перезапуск сервисов..."
    systemctl restart xray
    systemctl restart nginx
    sleep 1
    cmd_status
}

cmd_update_xray() {
    echo ""
    
    if ! is_xray_installed; then
        log_error "Xray не установлен"
        return 1
    fi
    
    local current=$(get_xray_version)
    local latest=$(get_latest_xray_version)
    
    echo "  Текущая:   $current"
    echo "  Последняя: $latest"
    echo ""
    
    if [ "$current" = "$latest" ]; then
        log_success "Уже последняя версия"
        return 0
    fi
    
    read -p "Обновить? [y/n]: " confirm
    if [ "$confirm" != "y" ]; then
        return 0
    fi
    
    create_backup
    
    log_info "Обновление..."
    install_xray_binary
    
    systemctl restart xray
    
    log_success "Обновлено: $current → $(get_xray_version)"
}

cmd_renew_ssl() {
    log_info "Принудительное обновление SSL..."
    
    if ! command_exists certbot; then
        log_error "Certbot не установлен"
        return 1
    fi
    
    if certbot renew --force-renewal; then
        systemctl restart xray
        log_success "Сертификат обновлён"
    else
        log_error "Ошибка обновления"
    fi
}

cmd_regenerate_subs() {
    local domain=$(get_domain)
    local sub_uri=$(get_sub_uri)
    
    echo ""
    log_warning "Перегенерация подписок"
    echo "Текущий домен: $domain"
    echo "Текущий путь: /$sub_uri/"
    echo ""
    
    read -p "Изменить домен? [y/n]: " change
    
    if [ "$change" = "y" ]; then
        read -p "Новый домен [$domain]: " new_domain
        new_domain="${new_domain:-$domain}"
        
        read -p "Новое секретное слово [Enter=оставить]: " new_seed
        if [ -n "$new_seed" ]; then
            sub_uri=$(to_base64 "$new_seed")
        fi
        
        set_install_info "domain" "$new_domain"
        set_install_info "subUri" "$sub_uri"
        
        configure_nginx_fallback "$new_domain" "$sub_uri"
        systemctl restart nginx
        
        domain="$new_domain"
    fi
    
    read -p "Продолжить? [y/n]: " confirm
    if [ "$confirm" != "y" ]; then
        return 0
    fi
    
    regenerate_all_subscriptions "$domain"
    
    log_success "Готово! Ссылки: https://$domain/$sub_uri/<user>"
}

cmd_accept_config() {
    echo ""
    log_warning "Принять текущий конфиг как эталон?"
    echo "Скрипт перестанет предупреждать об изменениях."
    echo ""
    
    read -p "Подтвердить? [y/n]: " confirm
    if [ "$confirm" = "y" ]; then
        save_config_hash
        log_success "Изменения приняты"
    fi
}

# ============================================================
# КОМАНДА: УСТАНОВКА
# ============================================================

cmd_install() {
    clear
    
    local saved_backup=""
    local old_domain=""
    
    # Проверка существующей установки
    if is_xray_installed; then
        echo -e "${YELLOW}Xray уже установлен${NC}"
        echo ""
        echo "  1. Переустановить (сохранить пользователей)"
        echo "  2. Чистая установка"
        echo "  0. Отмена"
        echo ""
        read -p "Выбор: " choice
        
        case "$choice" in
            1)
                saved_backup=$(create_backup)
                old_domain=$(get_domain)
                ;;
            2)
                read -p "Удалить всех пользователей? [y/n]: " confirm
                [ "$confirm" != "y" ] && return 0
                ;;
            *)
                return 0
                ;;
        esac
        
        systemctl stop xray nginx 2>/dev/null
    fi
    
    echo -e "${GREEN}Установка Xray + WARP${NC}"
    echo ""
    
    # Домен
    if [ -n "$old_domain" ]; then
        read -p "Домен [$old_domain]: " domain
        domain="${domain:-$old_domain}"
    else
        read -p "Домен: " domain
    fi
    
    if [ -z "$domain" ]; then
        log_error "Домен обязателен"
        return 1
    fi
    
    # Секретное слово
    echo ""
    read -p "Секретное слово [sub]: " seed_word
    seed_word="${seed_word:-sub}"
    local sub_uri=$(to_base64 "$seed_word")
    log_info "Путь подписок: /$sub_uri/"
    
    # Админ
    local admin_user="admin_$(generate_random_suffix)"
    log_info "Администратор: $admin_user"
    
    # Пакеты
    log_info "Установка пакетов..."
    apt update -q && apt upgrade -y -q
    apt install -y -q curl socat nginx certbot lsb-release jq qrencode
    
    # Директории
    rm -rf "$SUBS_DIR"
    mkdir -p "$SUBS_DIR" /var/www/html
    chmod 755 "$SUBS_DIR"
    chown www-data:www-data "$SUBS_DIR"
    
    # Sysctl
    apply_sysctl_tweaks
    
    # WARP
    local warp_result=$(generate_warp_keys)
    local warp_key=""
    local warp_addresses=""
    
    if [ -n "$warp_result" ]; then
        warp_key=$(echo "$warp_result" | cut -d'|' -f1)
        warp_addresses=$(echo "$warp_result" | cut -d'|' -f2)
    fi
    
    # Nginx для ACME
    configure_nginx_acme "$domain"
    systemctl restart nginx
    
    # SSL
    if ! obtain_ssl_certificate "$domain"; then
        log_error "Проверьте, что $domain указывает на IP сервера"
        return 1
    fi
    
    setup_ssl_renewal_hook
    
    # Xray binary
    install_xray_binary
    
    # Конфиг
    local cert_path="$CERT_BASE/$domain"
    local config_json=$(build_config "$cert_path" "$warp_key" "$warp_addresses")
    save_config "$config_json"
    
    # Добавляем админа
    local admin_uuid=$(generate_uuid)
    add_user_to_config "$admin_uuid" "$admin_user"
    
    # Nginx fallback
    configure_nginx_fallback "$domain" "$sub_uri"
    
    if [ ! -f "/var/www/html/index.html" ]; then
        echo "<h1>Welcome</h1>" > /var/www/html/index.html
    fi
    
    # Сохраняем info
    set_install_info "domain" "$domain"
    set_install_info "subUri" "$sub_uri"
    
    # Подписка админа
    create_subscription_file "$admin_user" "$admin_uuid" "$domain"
    
    # Восстановление пользователей
    if [ -n "$saved_backup" ]; then
        restore_users_from_backup "$saved_backup" "$admin_user" "$domain"
    fi
    
    # Хеш конфига
    save_config_hash
    
    # Запуск
    systemctl restart nginx xray
    systemctl enable xray nginx > /dev/null 2>&1
    
    sleep 2
    
    if is_service_running xray; then
        log_success "Xray запущен!"
    else
        log_error "Xray не запустился: journalctl -u xray -n 50"
    fi
    
    # Итоги
    echo ""
    log_success "Установка завершена"
    echo ""
    echo "  Пользователей: $(get_user_count)"
    echo "  Администратор: $admin_user"
    echo ""
    
    local sub_link=$(generate_sub_link "$domain" "$sub_uri" "$admin_user")
    echo -e "  Подписка: ${YELLOW}$sub_link${NC}"
    show_qr "$sub_link" "Подписка $admin_user"
}

cmd_uninstall() {
    echo ""
    echo -e "${RED}Удаление Xray${NC}"
    echo ""
    echo "  1. Удалить (сохранить бэкап)"
    echo "  2. Удалить полностью"
    echo "  0. Отмена"
    echo ""
    read -p "Выбор: " choice
    
    case "$choice" in
        1)
            create_backup
            log_success "Бэкап сохранён в $BACKUP_DIR"
            ;;
        2)
            read -p "Удалить ВСЁ включая бэкапы? [y/n]: " confirm
            [ "$confirm" != "y" ] && return 0
            rm -rf "$BACKUP_DIR"
            ;;
        *)
            return 0
            ;;
    esac
    
    log_info "Остановка сервисов..."
    systemctl stop xray
    systemctl disable xray > /dev/null 2>&1
    
    log_info "Удаление файлов..."
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
    
    log_success "Удалено"
    
    if dir_exists "$BACKUP_DIR"; then
        echo -e "${YELLOW}Бэкапы: $BACKUP_DIR${NC}"
    fi
}

cmd_restore_backup() {
    list_backups
    
    if ! dir_exists "$BACKUP_DIR"; then
        return 0
    fi
    
    echo ""
    read -p "Имя бэкапа: " backup_name
    
    if [ -z "$backup_name" ]; then
        return 0
    fi
    
    local backup_path="$BACKUP_DIR/$backup_name"
    
    if ! dir_exists "$backup_path"; then
        log_error "Бэкап не найден"
        return 1
    fi
    
    if ! file_exists "$INFO_FILE"; then
        log_error "Сначала установите Xray"
        return 1
    fi
    
    read -p "Восстановить из $backup_name? [y/n]: " confirm
    [ "$confirm" != "y" ] && return 0
    
    restore_users_from_backup "$backup_path" "" "$(get_domain)"
    systemctl restart xray
    
    log_success "Восстановлено"
}

# ============================================================
# МЕНЮ
# ============================================================

show_menu() {
    while true; do
        clear
        
        local config_changed=false
        check_config_integrity || config_changed=true
        
        echo -e "${CYAN}═══════════════════════════════════════${NC}"
        echo -e "${CYAN}          XRAY MANAGER v${VERSION}${NC}"
        echo -e "${CYAN}═══════════════════════════════════════${NC}"
        
        local status=$(get_status)
        
        case $status in
            running)
                echo -e "  Статус: ${GREEN}● Работает${NC}"
                echo -e "  Домен:  $(get_domain)"
                echo -e "  Users:  $(get_user_count)"
                ;;
            stopped)
                echo -e "  Статус: ${RED}● Остановлен${NC}"
                echo -e "  Домен:  $(get_domain)"
                ;;
            not_installed)
                echo -e "  Статус: ${GRAY}○ Не установлен${NC}"
                ;;
        esac
        
        if [ "$config_changed" = true ]; then
            echo -e "  ${RED}⚠ Конфиг изменён!${NC}"
        fi
        
        echo -e "${CYAN}───────────────────────────────────────${NC}"
        
        if [ "$status" != "not_installed" ]; then
            echo -e "${YELLOW} Пользователи${NC}"
            echo "  1. Список"
            echo "  2. Добавить"
            echo "  3. Показать"
            echo "  4. Удалить"
            echo ""
            echo -e "${YELLOW} Система${NC}"
            echo "  5. Health check"
            echo "  6. Перезапустить"
            echo "  7. Обновить Xray"
            echo "  8. Обновить SSL"
            echo ""
            echo -e "${YELLOW} Подписки${NC}"
            echo "  9. Перегенерировать все"
            echo "  10. Бэкапы"
            echo "  11. Восстановить"
            
            if [ "$config_changed" = true ]; then
                echo ""
                echo -e "${RED} Конфиг${NC}"
                echo "  12. Принять изменения"
            fi
            
            echo ""
            echo -e "${GRAY}  20. Переустановить${NC}"
            echo -e "${GRAY}  21. Удалить${NC}"
        else
            echo ""
            echo "  1. Установить"
            
            if dir_exists "$BACKUP_DIR" && [ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
                echo -e "${YELLOW}  2. Показать бэкапы${NC}"
            fi
        fi
        
        echo ""
        echo "  0. Выход"
        echo -e "${CYAN}───────────────────────────────────────${NC}"
        read -p "  > " choice
        
        if [ "$status" = "not_installed" ]; then
            case "$choice" in
                1) cmd_install; read -p "Enter..." ;;
                2) list_backups; read -p "Enter..." ;;
                0) exit 0 ;;
            esac
        else
            case "$choice" in
                1)  cmd_list_users; read -p "Enter..." ;;
                2)  cmd_add_user; read -p "Enter..." ;;
                3)  cmd_show_user; read -p "Enter..." ;;
                4)  cmd_delete_user; read -p "Enter..." ;;
                5)  cmd_health_check; read -p "Enter..." ;;
                6)  cmd_restart; read -p "Enter..." ;;
                7)  cmd_update_xray; read -p "Enter..." ;;
                8)  cmd_renew_ssl; read -p "Enter..." ;;
                9)  cmd_regenerate_subs; read -p "Enter..." ;;
                10) list_backups; read -p "Enter..." ;;
                11) cmd_restore_backup; read -p "Enter..." ;;
                12) cmd_accept_config; read -p "Enter..." ;;
                20) cmd_install; read -p "Enter..." ;;
                21) cmd_uninstall; read -p "Enter..." ;;
                0)  exit 0 ;;
            esac
        fi
    done
}

show_help() {
    cat <<EOF
Xray Manager v$VERSION

Использование: $0 [команда] [аргументы]

Пользователи:
  list              Список пользователей
  add <name>        Добавить пользователя
  show <name>       Показать данные
  del <name>        Удалить

Система:
  install           Установить
  health            Проверка системы
  status            Статус сервисов
  restart           Перезапустить
  update            Обновить Xray
  renew             Обновить SSL

Подписки:
  regen             Перегенерировать все
  backup            Создать бэкап
  backups           Список бэкапов
  restore           Восстановить

Прочее:
  accept-config     Принять изменения конфига
  remove            Удалить Xray
  help              Справка
EOF
}

# ============================================================
# MAIN
# ============================================================

require_root

# Проверка зависимостей
if [ "$(get_status)" != "not_installed" ]; then
    for cmd in jq curl; do
        if ! command_exists "$cmd"; then
            apt update -q && apt install -y "$cmd"
        fi
    done
fi

if [ $# -eq 0 ]; then
    show_menu
else
    case "$1" in
        install)        cmd_install ;;
        list)           cmd_list_users ;;
        add)            cmd_add_user "$2" ;;
        show)           cmd_show_user "$2" ;;
        del)            cmd_delete_user "$2" ;;
        health)         cmd_health_check ;;
        status)         cmd_status ;;
        restart)        cmd_restart ;;
        update)         cmd_update_xray ;;
        renew)          cmd_renew_ssl ;;
        regen)          cmd_regenerate_subs ;;
        backup)         create_backup ;;
        backups)        list_backups ;;
        restore)        cmd_restore_backup ;;
        accept-config)  cmd_accept_config ;;
        remove)         cmd_uninstall ;;
        help|-h|--help) show_help ;;
        *)              show_help; exit 1 ;;
    esac
fi
