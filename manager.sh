#!/bin/bash

infoFile="/usr/local/etc/xray/install_info.txt"
configFile="/usr/local/etc/xray/config.json"
subsDir="/var/www/html/subs"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[1;33m'
nc='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${red}Запустите скрипт с правами root.${nc}"
  exit 1
fi

function logInfo() { echo -e "${yellow}• $1${nc}"; }
function logSuccess() { echo -e "${green}✓ $1${nc}"; }
function logError() { echo -e "${red}✕ $1${nc}"; }

function showQr() {
    local data="$1"
    local label="$2"
    echo ""
    echo -e "${yellow}QR Code: $label${nc}"
    if command -v qrencode &> /dev/null; then
        qrencode -t ANSIUTF8 "$data"
    else
        echo -e "${red}qrencode не установлен, QR не может быть отображен.${nc}"
    fi
    echo ""
}

function toBase64() {
    echo -n "$1" | base64 | tr '+/' '-_' | tr -d '='
}

function installNode() {
    clear
    
    if [ -f "/usr/local/bin/xray" ]; then
        echo -e "${yellow}Внимание: Xray уже установлен!${nc}"
        read -p "Переустановить? Текущая конфигурация будет удалена (y/n): " reinstall
        if [[ "$reinstall" != "y" ]]; then
            echo "Установка отменена."
            return
        fi
        systemctl stop xray
        systemctl stop nginx
    fi

    echo -e "${green}Установка Xray + WARP + Individual Subs${nc}\n"

    read -p "Введите доменное имя: " domain
    if [ -z "$domain" ]; then logError "Домен обязателен."; exit 1; fi

    echo ""
    echo "Придумайте секретное слово (оно будет закодировано в Base64)."
    read -p "Секретное слово (Enter для 'sub'): " seedWord
    
    if [ -z "$seedWord" ]; then
        seedWord="sub"
    fi
    
    subUri=$(toBase64 "$seedWord")
    logInfo "Путь сгенерирован (Base64): /$subUri/"

    randSuffix=$(head /dev/urandom | tr -dc a-z0-9 | head -c 5)
    adminUser="admin_$randSuffix"
    logInfo "Создается администратор: $adminUser"

    logInfo "Обновление пакетов..."
    apt update -q && apt upgrade -y -q
    apt install -y -q curl socat nginx certbot lsb-release jq qrencode

    rm -rf $subsDir
    mkdir -p $subsDir
    chmod 755 $subsDir

    uuid=$(cat /proc/sys/kernel/random/uuid)
    certPath="/etc/letsencrypt/live/$domain"

    cat > /etc/sysctl.d/99-xray-performance.conf <<EOF
fs.file-max = 1000000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.somaxconn = 65535
net.ipv4.tcp_keepalive_time = 600
EOF
    sysctl --system > /dev/null 2>&1

    logInfo "Генерация ключей WARP..."
    wget -qO wgcf https://github.com/ViRb3/wgcf/releases/download/v2.2.22/wgcf_2.2.22_linux_amd64
    chmod +x wgcf

    ./wgcf register --accept-tos > /dev/null 2>&1
    ./wgcf generate > /dev/null 2>&1

    if [ ! -f wgcf-profile.conf ]; then
        logError "Ошибка генерации WARP конфига."
        exit 1
    fi

    warpPrivateKey=$(grep "PrivateKey" wgcf-profile.conf | cut -d' ' -f3)
    warpIpv6=$(grep "Address" wgcf-profile.conf | sed -n '2p' | cut -d' ' -f3 | cut -d'/' -f1)
    rm wgcf wgcf-account.toml wgcf-profile.conf

    logInfo "Получение SSL..."
    systemctl stop nginx
    systemctl stop xray 2>/dev/null
    
    certbot certonly --standalone --preferred-challenges http -d $domain --non-interactive --agree-tos -m admin@$domain

    if [ ! -f "$certPath/fullchain.pem" ]; then
        logError "Ошибка получения сертификата."
        echo "Попробуйте выполнить вручную: certbot certonly --standalone -d $domain"
        exit 1
    fi

    logInfo "Установка Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install > /dev/null 2>&1

    sed -i 's/User=nobody/User=root/' /etc/systemd/system/xray.service
    sed -i '/^CapabilityBoundingSet/d' /etc/systemd/system/xray.service
    sed -i '/^AmbientCapabilities/d' /etc/systemd/system/xray.service
    systemctl daemon-reload

    mkdir -p /usr/local/etc/xray
    cat > $configFile <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "flow": "xtls-rprx-vision",
            "level": 0,
            "email": "$adminUser"
          }
        ],
        "decryption": "none",
        "fallbacks": [ { "dest": 8080 } ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$certPath/fullchain.pem",
              "keyFile": "$certPath/privkey.pem"
            }
          ],
          "minVersion": "1.2",
          "alpn": ["http/1.1", "h2"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "warp",
      "protocol": "wireguard",
      "settings": {
        "secretKey": "$warpPrivateKey",
        "address": [ "172.16.0.2/32", "$warpIpv6/128" ],
        "peers": [
          {
            "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "endpoint": "engage.cloudflareclient.com:2408",
            "keepAlive": 15
          }
        ],
        "mtu": 1280
      }
    },
    { "tag": "block", "protocol": "blackhole" },
    { "tag": "direct", "protocol": "freedom" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "outboundTag": "block", "ip": ["geoip:private"] }
    ]
  }
}
EOF

    logInfo "Настройка Nginx..."
    rm /etc/nginx/sites-enabled/default 2>/dev/null
    cat > /etc/nginx/conf.d/fallback.conf <<EOF
server {
    listen 127.0.0.1:8080;
    server_name $domain;
    root /var/www/html;
    index index.html;
    
    location /$subUri/ {
        alias $subsDir/;
        default_type text/plain;
        autoindex off;
    }
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    if [ ! -f "/var/www/html/index.html" ]; then
        mkdir -p /var/www/html
        echo "<h1>Welcome to nginx!</h1>" > /var/www/html/index.html
    fi

    echo "domain=$domain" > $infoFile
    echo "subUri=$subUri" >> $infoFile

    adminFilename=$(toBase64 "$adminUser")
    vlessLink="vless://$uuid@$domain:443?security=tls&encryption=none&flow=xtls-rprx-vision&fp=chrome&type=tcp&sni=$domain#$domain-admin"
    
    echo -n "$vlessLink" | base64 -w 0 > "$subsDir/$adminFilename"
    chmod 644 "$subsDir/$adminFilename"
    
    subLink="https://$domain/$subUri/$adminFilename"

    systemctl restart nginx
    systemctl restart xray
    systemctl enable xray > /dev/null 2>&1
    systemctl enable nginx > /dev/null 2>&1

    echo ""
    logSuccess "Установка завершена."
    
    echo -e "Пользователь: $adminUser"
    echo -e "Личная ссылка подписки: $subLink"
    showQr "$subLink" "Подписка $adminUser"
    
    echo -e "Ключ VLESS: $vlessLink"
    showQr "$vlessLink" "Ключ $adminUser"
}

function addUser() {
    local userName=$1

    if [ ! -f "$infoFile" ]; then logError "Файл конфигурации не найден."; exit 1; fi
    source $infoFile

    if [[ -z "$userName" ]]; then
        read -p "Имя нового пользователя (latin): " userName
    fi

    if [[ -z "$userName" ]]; then logError "Имя обязательно."; return; fi

    userFilename=$(toBase64 "$userName")
    if [ -f "$subsDir/$userFilename" ]; then
        logError "Пользователь $userName уже существует (файл найден)."
        return
    fi

    local newUuid=$(cat /proc/sys/kernel/random/uuid)

    cp $configFile "${configFile}.bak"
    jq --arg uuid "$newUuid" --arg email "$userName" \
       '.inbounds[0].settings.clients += [{"id": $uuid, "flow": "xtls-rprx-vision", "level": 0, "email": $email}]' \
       $configFile > temp.json && mv temp.json $configFile

    systemctl restart xray

    local newLink="vless://$newUuid@$domain:443?security=tls&encryption=none&flow=xtls-rprx-vision&fp=chrome&type=tcp&sni=$domain#$domain-$userName"
    local subLink="https://$domain/$subUri/$userFilename"

    echo -n "$newLink" | base64 -w 0 > "$subsDir/$userFilename"
    chmod 644 "$subsDir/$userFilename"

    logSuccess "Пользователь $userName добавлен."
    echo "ID файла: $userFilename"
    
    echo "---------------------------------------------------"
    echo -e "${yellow}Личная ссылка подписки:${nc} $subLink"
    showQr "$subLink" "Подписка для $userName"
    echo "---------------------------------------------------"
}

function showUserInfo() {
    local targetUser=$1

    if [ ! -f "$infoFile" ]; then logError "Файл конфигурации не найден."; exit 1; fi
    source $infoFile

    if [[ -z "$targetUser" ]]; then
        echo -e "${yellow}Список пользователей:${nc}"
        jq -r '.inbounds[0].settings.clients[] | .email' $configFile
        echo "--------------------------------"
        read -p "Введите имя пользователя для просмотра: " targetUser
    fi

    if [[ -z "$targetUser" ]]; then echo "Отмена."; return; fi

    local userUuid=$(jq -r --arg email "$targetUser" '.inbounds[0].settings.clients[] | select(.email == $email) | .id' $configFile)

    if [[ -z "$userUuid" ]]; then
        logError "Пользователь $targetUser не найден в конфиге."
        return
    fi

    local userFilename=$(toBase64 "$targetUser")
    local subLink="https://$domain/$subUri/$userFilename"
    local vlessLink="vless://$userUuid@$domain:443?security=tls&encryption=none&flow=xtls-rprx-vision&fp=chrome&type=tcp&sni=$domain#$domain-$targetUser"

    if [ ! -f "$subsDir/$userFilename" ]; then
        echo -n "$vlessLink" | base64 -w 0 > "$subsDir/$userFilename"
        chmod 644 "$subsDir/$userFilename"
        logInfo "Файл подписки был восстановлен."
    fi

    clear
    echo -e "${green}Данные пользователя: $targetUser${nc}"
    echo "---------------------------------------------------"
    
    echo -e "1. Ссылка подписки (для приложения):"
    echo -e "${yellow}$subLink${nc}"
    showQr "$subLink" "Подписка для $targetUser"
    
    echo "---------------------------------------------------"
    echo -e "2. Ключ VLESS (для ручного ввода):"
    echo -e "${yellow}$vlessLink${nc}"
    showQr "$vlessLink" "Ключ VLESS"
}

function deleteUser() {
    local userName=$1

    if [ ! -f "$infoFile" ]; then logError "Файл конфигурации не найден."; exit 1; fi
    source $infoFile

    if [[ -z "$userName" ]]; then
        echo -e "${yellow}Активные пользователи:${nc}"
        jq -r '.inbounds[0].settings.clients[] | .email' $configFile
        echo ""
        read -p "Введите имя для удаления: " userName
    fi

    if [[ -z "$userName" ]]; then echo "Отмена."; return; fi

    local userExists=$(jq --arg email "$userName" '.inbounds[0].settings.clients[] | select(.email == $email) | .email' $configFile)
    if [[ -z "$userExists" ]]; then logError "Пользователь не найден в конфиге."; return; fi

    cp $configFile "${configFile}.bak"
    jq --arg email "$userName" 'del(.inbounds[0].settings.clients[] | select(.email == $email))' $configFile > temp.json && mv temp.json $configFile

    systemctl restart xray

    userFilename=$(toBase64 "$userName")
    if [ -f "$subsDir/$userFilename" ]; then
        rm "$subsDir/$userFilename"
        logSuccess "Файл подписки для $userName удален."
    else
        logInfo "Файл подписки не найден."
    fi

    logSuccess "Пользователь $userName удален."
}

function uninstallXray() {
    read -p "Вы уверены, что хотите полностью удалить Xray? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi

    logInfo "Остановка сервисов..."
    systemctl stop xray
    systemctl disable xray > /dev/null 2>&1
    
    logInfo "Удаление файлов..."
    rm -rf /usr/local/bin/xray
    rm -rf /usr/local/etc/xray
    rm -rf /usr/local/share/xray
    rm -rf /var/www/html/subs
    rm -f /etc/systemd/system/xray.service
    rm -f /etc/nginx/conf.d/fallback.conf
    rm -f /etc/sysctl.d/99-xray-performance.conf
    
    systemctl daemon-reload
    systemctl restart nginx
    
    logSuccess "Система очищена."
}

function showMenu() {
    while true; do
        clear
        echo -e "${green}Xray Manager (Individual Subs)${nc}"
        echo "1. Установить"
        echo "2. Добавить пользователя"
        echo "3. Показать пользователя / QR"
        echo "4. Удалить пользователя"
        echo "5. Удалить Xray"
        echo "0. Выход"
        echo ""
        read -p "> " choice

        case "$choice" in
            1) installNode; read -p "Нажмите Enter..." ;;
            2) addUser; read -p "Нажмите Enter..." ;;
            3) showUserInfo; read -p "Нажмите Enter..." ;;
            4) deleteUser; read -p "Нажмите Enter..." ;;
            5) uninstallXray; read -p "Нажмите Enter..." ;;
            0) exit ;;
            *) ;;
        esac
    done
}

function showHelp() {
    echo "Использование: $0 [команда]"
    echo "  install         - Установка"
    echo "  add <name>      - Добавить пользователя"
    echo "  show <name>     - Показать QR и ссылки пользователя"
    echo "  del <name>      - Удалить пользователя"
    echo "  remove          - Удалить всё"
}

if [ $# -eq 0 ]; then
    showMenu
else
    case "$1" in
        install) installNode ;;
        add)     addUser "$2" ;;
        show|list) showUserInfo "$2" ;;
        del)     deleteUser "$2" ;;
        remove)  uninstallXray ;;
        help)    showHelp ;;
        *)       showHelp ;;
    esac
fi
