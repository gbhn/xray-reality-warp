#!/bin/bash

infoFile="/usr/local/etc/xray/install_info.txt"
configFile="/usr/local/etc/xray/config.json"
subsDir="/var/www/html/subs"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[1;33m'
cyan='\033[0;36m'
gray='\033[0;90m'
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
    echo -e "${yellow}QR: $label${nc}"
    if command -v qrencode &> /dev/null; then
        qrencode -t ANSIUTF8 "$data"
    else
        echo -e "${red}qrencode не установлен.${nc}"
    fi
    echo ""
}

function toBase64() {
    echo -n "$1" | base64 | tr '+/' '-_' | tr -d '='
}

function getStatus() {
    if [ ! -f "/usr/local/bin/xray" ]; then
        echo "not_installed"
    elif systemctl is-active --quiet xray; then
        echo "running"
    else
        echo "stopped"
    fi
}

function getUserCount() {
    if [ -f "$configFile" ]; then
        jq -r '.inbounds[0].settings.clients | length' $configFile 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

function getDomain() {
    if [ -f "$infoFile" ]; then
        grep "domain=" $infoFile | cut -d'=' -f2
    else
        echo "-"
    fi
}

function healthCheck() {
    echo ""
    logInfo "Проверка системы..."
    echo ""
    echo "─────────────────────────────────────"
    
    local issues=0
    
    # Xray
    if systemctl is-active --quiet xray; then
        echo -e "  Xray:        ${green}✓ работает${nc}"
    else
        echo -e "  Xray:        ${red}✕ остановлен${nc}"
        ((issues++))
    fi
    
    # Nginx
    if systemctl is-active --quiet nginx; then
        echo -e "  Nginx:       ${green}✓ работает${nc}"
    else
        echo -e "  Nginx:       ${red}✕ остановлен${nc}"
        ((issues++))
    fi
    
    # Порт 443
    if ss -tlnp | grep -q ':443'; then
        echo -e "  Порт 443:    ${green}✓ открыт${nc}"
    else
        echo -e "  Порт 443:    ${red}✕ закрыт${nc}"
        ((issues++))
    fi
    
    # Конфиг Xray
    if [ -f "$configFile" ]; then
        if /usr/local/bin/xray run -test -config $configFile > /dev/null 2>&1; then
            echo -e "  Конфиг:      ${green}✓ валидный${nc}"
        else
            echo -e "  Конфиг:      ${red}✕ ошибка${nc}"
            ((issues++))
        fi
    else
        echo -e "  Конфиг:      ${red}✕ не найден${nc}"
        ((issues++))
    fi
    
    # SSL сертификат
    if [ -f "$infoFile" ]; then
        source $infoFile
        local certPath="/etc/letsencrypt/live/$domain"
        
        if [ -f "$certPath/fullchain.pem" ]; then
            local expiry=$(openssl x509 -enddate -noout -in "$certPath/fullchain.pem" 2>/dev/null | cut -d= -f2)
            if [ -n "$expiry" ]; then
                local expiryEpoch=$(date -d "$expiry" +%s 2>/dev/null)
                local nowEpoch=$(date +%s)
                local daysLeft=$(( (expiryEpoch - nowEpoch) / 86400 ))
                
                if [ $daysLeft -gt 30 ]; then
                    echo -e "  SSL:         ${green}✓ $daysLeft дней${nc}"
                elif [ $daysLeft -gt 7 ]; then
                    echo -e "  SSL:         ${yellow}⚠ $daysLeft дней${nc}"
                    ((issues++))
                else
                    echo -e "  SSL:         ${red}✕ $daysLeft дней!${nc}"
                    ((issues++))
                fi
            fi
        else
            echo -e "  SSL:         ${red}✕ не найден${nc}"
            ((issues++))
        fi
    fi
    
    # Версия Xray
    if [ -f "/usr/local/bin/xray" ]; then
        local currentVersion=$(/usr/local/bin/xray version 2>/dev/null | head -n1 | awk '{print $2}')
        local latestVersion=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null | jq -r '.tag_name' | tr -d 'v')
        
        if [ -n "$currentVersion" ] && [ -n "$latestVersion" ]; then
            if [ "$currentVersion" = "$latestVersion" ]; then
                echo -e "  Версия:      ${green}✓ $currentVersion${nc}"
            else
                echo -e "  Версия:      ${yellow}⚠ $currentVersion → $latestVersion${nc}"
            fi
        else
            echo -e "  Версия:      ${gray}$currentVersion${nc}"
        fi
    fi
    
    echo "─────────────────────────────────────"
    echo ""
    
    if [ $issues -eq 0 ]; then
        logSuccess "Все проверки пройдены."
    else
        logError "Обнаружено проблем: $issues"
    fi
}

function updateXray() {
    echo ""
    
    if [ ! -f "/usr/local/bin/xray" ]; then
        logError "Xray не установлен."
        return
    fi
    
    local currentVersion=$(/usr/local/bin/xray version 2>/dev/null | head -n1 | awk '{print $2}')
    local latestVersion=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name' | tr -d 'v')
    
    echo "  Текущая версия:  $currentVersion"
    echo "  Последняя версия: $latestVersion"
    echo ""
    
    if [ "$currentVersion" = "$latestVersion" ]; then
        logSuccess "Уже установлена последняя версия."
        return
    fi
    
    read -p "Обновить Xray? [y/n]: " confirm
    if [[ "$confirm" != "y" ]]; then
        echo "Отменено."
        return
    fi
    
    logInfo "Создание бэкапа конфигурации..."
    cp $configFile "${configFile}.backup_$(date +%Y%m%d_%H%M%S)"
    
    logInfo "Обновление Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        sed -i 's/User=nobody/User=root/' /etc/systemd/system/xray.service
        sed -i '/^CapabilityBoundingSet/d' /etc/systemd/system/xray.service
        sed -i '/^AmbientCapabilities/d' /etc/systemd/system/xray.service
        systemctl daemon-reload
        systemctl restart xray
        
        local newVersion=$(/usr/local/bin/xray version 2>/dev/null | head -n1 | awk '{print $2}')
        logSuccess "Xray обновлен: $currentVersion → $newVersion"
    else
        logError "Ошибка обновления."
    fi
}

function showStatus() {
    echo ""
    logInfo "Статус сервисов..."
    echo ""
    
    local xrayStatus=$(systemctl is-active xray 2>/dev/null)
    local nginxStatus=$(systemctl is-active nginx 2>/dev/null)
    
    if [ "$xrayStatus" = "active" ]; then
        echo -e "  Xray:  ${green}●${nc} работает"
    else
        echo -e "  Xray:  ${red}●${nc} остановлен"
    fi
    
    if [ "$nginxStatus" = "active" ]; then
        echo -e "  Nginx: ${green}●${nc} работает"
    else
        echo -e "  Nginx: ${red}●${nc} остановлен"
    fi
    
    echo ""
    if [ -f "$configFile" ]; then
        local count=$(getUserCount)
        echo "  Пользователей: $count"
    fi
}

function restartServices() {
    logInfo "Перезапуск сервисов..."
    systemctl restart xray
    systemctl restart nginx
    sleep 1
    showStatus
}

function listUsers() {
    if [ ! -f "$configFile" ]; then
        logError "Конфигурация не найдена."
        return
    fi
    
    echo ""
    echo -e "${cyan}Пользователи:${nc}"
    echo "─────────────────────────────"
    
    local users=$(jq -r '.inbounds[0].settings.clients[] | .email' $configFile 2>/dev/null)
    
    if [ -z "$users" ]; then
        echo -e "${gray}  Нет пользователей${nc}"
    else
        local i=1
        while IFS= read -r user; do
            echo -e "  $i. $user"
            ((i++))
        done <<< "$users"
    fi
    
    echo "─────────────────────────────"
    echo ""
}

function installNode() {
    clear
    
    if [ -f "/usr/local/bin/xray" ]; then
        echo -e "${yellow}Xray уже установлен.${nc}"
        read -p "Переустановить? Конфигурация будет удалена [y/n]: " reinstall
        if [[ "$reinstall" != "y" ]]; then
            echo "Отменено."
            return
        fi
        systemctl stop xray
        systemctl stop nginx
    fi

    echo -e "${green}Установка Xray + WARP${nc}\n"

    read -p "Домен: " domain
    if [ -z "$domain" ]; then logError "Домен обязателен."; exit 1; fi

    echo ""
    echo "Секретное слово будет закодировано в Base64."
    read -p "Секретное слово [по умолчанию: sub]: " seedWord
    
    if [ -z "$seedWord" ]; then
        seedWord="sub"
    fi
    
    subUri=$(toBase64 "$seedWord")
    logInfo "Путь: /$subUri/"

    randSuffix=$(head /dev/urandom | tr -dc a-z0-9 | head -c 5)
    adminUser="admin_$randSuffix"
    logInfo "Администратор: $adminUser"

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
    
    latestWgcf=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | jq -r '.tag_name' | tr -d 'v')
    wget -qO wgcf "https://github.com/ViRb3/wgcf/releases/download/v${latestWgcf}/wgcf_${latestWgcf}_linux_amd64"
    
    if [ ! -f wgcf ]; then
        logError "Ошибка скачивания wgcf."
        exit 1
    fi
    
    chmod +x wgcf

    ./wgcf register --accept-tos > /dev/null 2>&1
    ./wgcf generate > /dev/null 2>&1

    if [ ! -f wgcf-profile.conf ]; then
        logError "Ошибка генерации WARP."
        exit 1
    fi

    warpPrivateKey=$(grep "PrivateKey" wgcf-profile.conf | cut -d' ' -f3)
    warpIpv6=$(grep "Address" wgcf-profile.conf | sed -n '2p' | cut -d' ' -f3 | cut -d'/' -f1)
    rm -f wgcf wgcf-account.toml wgcf-profile.conf

    logInfo "Получение SSL..."
    systemctl stop nginx
    systemctl stop xray 2>/dev/null
    
    certbot certonly --standalone --preferred-challenges http -d $domain --non-interactive --agree-tos -m admin@$domain

    if [ ! -f "$certPath/fullchain.pem" ]; then
        logError "Ошибка получения сертификата."
        echo "Попробуйте: certbot certonly --standalone -d $domain"
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
    echo -e "Ссылка подписки: $subLink"
    showQr "$subLink" "Подписка $adminUser"
    
    echo -e "Ключ VLESS: $vlessLink"
    showQr "$vlessLink" "Ключ $adminUser"
}

function addUser() {
    local userName=$1

    if [ ! -f "$infoFile" ]; then logError "Конфигурация не найдена."; exit 1; fi
    source $infoFile

    if [[ -z "$userName" ]]; then
        listUsers
        read -p "Имя нового пользователя: " userName
    fi

    if [[ -z "$userName" ]]; then logError "Имя обязательно."; return; fi

    userFilename=$(toBase64 "$userName")
    if [ -f "$subsDir/$userFilename" ]; then
        logError "Пользователь $userName уже существует."
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
    
    echo ""
    echo -e "${yellow}Ссылка подписки:${nc} $subLink"
    showQr "$subLink" "Подписка $userName"
}

function showUserInfo() {
    local targetUser=$1

    if [ ! -f "$infoFile" ]; then logError "Конфигурация не найдена."; exit 1; fi
    source $infoFile

    if [[ -z "$targetUser" ]]; then
        listUsers
        read -p "Имя пользователя: " targetUser
    fi

    if [[ -z "$targetUser" ]]; then echo "Отменено."; return; fi

    local userUuid=$(jq -r --arg email "$targetUser" '.inbounds[0].settings.clients[] | select(.email == $email) | .id' $configFile)

    if [[ -z "$userUuid" ]]; then
        logError "Пользователь $targetUser не найден."
        return
    fi

    local userFilename=$(toBase64 "$targetUser")
    local subLink="https://$domain/$subUri/$userFilename"
    local vlessLink="vless://$userUuid@$domain:443?security=tls&encryption=none&flow=xtls-rprx-vision&fp=chrome&type=tcp&sni=$domain#$domain-$targetUser"

    if [ ! -f "$subsDir/$userFilename" ]; then
        echo -n "$vlessLink" | base64 -w 0 > "$subsDir/$userFilename"
        chmod 644 "$subsDir/$userFilename"
        logInfo "Файл подписки восстановлен."
    fi

    clear
    echo -e "${green}Пользователь: $targetUser${nc}"
    echo "─────────────────────────────────────────"
    
    echo -e "Ссылка подписки:"
    echo -e "${yellow}$subLink${nc}"
    showQr "$subLink" "Подписка $targetUser"
    
    echo "─────────────────────────────────────────"
    echo -e "Ключ VLESS:"
    echo -e "${yellow}$vlessLink${nc}"
    showQr "$vlessLink" "Ключ VLESS"
}

function deleteUser() {
    local userName=$1

    if [ ! -f "$infoFile" ]; then logError "Конфигурация не найдена."; exit 1; fi
    source $infoFile

    if [[ -z "$userName" ]]; then
        listUsers
        read -p "Имя для удаления: " userName
    fi

    if [[ -z "$userName" ]]; then echo "Отменено."; return; fi

    local userExists=$(jq --arg email "$userName" '.inbounds[0].settings.clients[] | select(.email == $email) | .email' $configFile)
    if [[ -z "$userExists" ]]; then logError "Пользователь не найден."; return; fi

    read -p "Удалить $userName? [y/n]: " confirm
    if [[ "$confirm" != "y" ]]; then echo "Отменено."; return; fi

    cp $configFile "${configFile}.bak"
    jq --arg email "$userName" 'del(.inbounds[0].settings.clients[] | select(.email == $email))' $configFile > temp.json && mv temp.json $configFile

    systemctl restart xray

    userFilename=$(toBase64 "$userName")
    if [ -f "$subsDir/$userFilename" ]; then
        rm "$subsDir/$userFilename"
    fi

    logSuccess "Пользователь $userName удален."
}

function uninstallXray() {
    echo ""
    echo -e "${red}Внимание: все данные будут удалены!${nc}"
    read -p "Удалить Xray полностью? [y/n]: " confirm
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
        
        echo -e "${cyan}═══════════════════════════════════════${nc}"
        echo -e "${cyan}           XRAY MANAGER${nc}"
        echo -e "${cyan}═══════════════════════════════════════${nc}"
        
        local status=$(getStatus)
        local domain=$(getDomain)
        
        case $status in
            "running")
                echo -e "  Статус: ${green}● Работает${nc}"
                echo -e "  Домен:  $domain"
                echo -e "  Пользователей: $(getUserCount)"
                ;;
            "stopped")
                echo -e "  Статус: ${red}● Остановлен${nc}"
                echo -e "  Домен:  $domain"
                ;;
            "not_installed")
                echo -e "  Статус: ${gray}○ Не установлен${nc}"
                ;;
        esac
        
        echo -e "${cyan}───────────────────────────────────────${nc}"
        
        if [ "$status" != "not_installed" ]; then
            echo -e "${yellow} Пользователи${nc}"
            echo "  1. Список"
            echo "  2. Добавить"
            echo "  3. Показать данные"
            echo "  4. Удалить"
            echo ""
            echo -e "${yellow} Система${nc}"
            echo "  5. Health check"
            echo "  6. Перезапустить"
            echo "  7. Обновить Xray"
            echo ""
            echo -e "${gray}  8. Переустановить${nc}"
            echo -e "${gray}  9. Удалить Xray${nc}"
        else
            echo ""
            echo "  1. Установить Xray"
        fi
        
        echo ""
        echo "  0. Выход"
        echo -e "${cyan}───────────────────────────────────────${nc}"
        read -p "  > " choice

        if [ "$status" = "not_installed" ]; then
            case "$choice" in
                1) installNode; read -p "Enter..." ;;
                0) exit ;;
                *) ;;
            esac
        else
            case "$choice" in
                1) listUsers; read -p "Enter..." ;;
                2) addUser; read -p "Enter..." ;;
                3) showUserInfo; read -p "Enter..." ;;
                4) deleteUser; read -p "Enter..." ;;
                5) healthCheck; read -p "Enter..." ;;
                6) restartServices; read -p "Enter..." ;;
                7) updateXray; read -p "Enter..." ;;
                8) installNode; read -p "Enter..." ;;
                9) uninstallXray; read -p "Enter..." ;;
                0) exit ;;
                *) ;;
            esac
        fi
    done
}

function showHelp() {
    echo "Использование: $0 [команда]"
    echo ""
    echo "  install       - Установить Xray"
    echo "  add <name>    - Добавить пользователя"
    echo "  show <name>   - Показать данные пользователя"
    echo "  list          - Список пользователей"
    echo "  del <name>    - Удалить пользователя"
    echo "  health        - Проверка системы"
    echo "  status        - Статус сервисов"
    echo "  restart       - Перезапустить"
    echo "  update        - Обновить Xray"
    echo "  remove        - Удалить Xray"
}

if [ $# -eq 0 ]; then
    showMenu
else
    case "$1" in
        install)  installNode ;;
        add)      addUser "$2" ;;
        show)     showUserInfo "$2" ;;
        list)     listUsers ;;
        del)      deleteUser "$2" ;;
        health)   healthCheck ;;
        status)   showStatus ;;
        restart)  restartServices ;;
        update)   updateXray ;;
        remove)   uninstallXray ;;
        help|-h)  showHelp ;;
        *)        showHelp ;;
    esac
fi
