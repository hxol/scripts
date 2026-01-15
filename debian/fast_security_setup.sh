#!/bin/bash
#
# Idempotent Fast Security Setup v2.0
# Last Updated: 2025-07-28
#
# 此脚本执行必要的安全加固操作。
# 幂等性保证:多次运行此脚本将使系统状态保持完全一致。它会覆盖现有配置以确保一致性。
#
# 核心任务:
# 1. 软件:安装所需软件包(apt 管理状态)。
# 2. 用户:创建/更新用户,强制更新密码,强制加入 sudo 用户组。
# 3. SSH:备份配置文件,覆盖 sshd_config 文件,重启服务。
# 4. 密钥:备份旧密钥,使用单个允许的密钥覆盖 authorized_keys 文件。
# 5. 防火墙:重置 UFW,移除冲突的防火墙规则,强制执行新规则。
#
# 用法:
# 方式 A:交互式模式(推荐，最不容易出错)
# wget -O setup.sh https://raw.githubusercontent.com/你的用户名/仓库/main/safe_setup.sh && chmod +x setup.sh && bash setup.sh
# 方式 B:一键命令行模式
# wget -O setup.sh https://raw.githubusercontent.com/你的用户名/仓库/main/safe_setup.sh && chmod +x setup.sh && bash setup.sh -u 用户名 -P SSH端口号 -k "公钥内容"
#
# 注意,"方式 B:一键命令行模式" 里的公钥需要包裹在双引号里
# 注意,使用 "方式 B:一键命令行模式" 后要运行命令 `history -c` 清除历史记录，防止密码留在 bash history 中。

# 颜色设置
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
RED='\033[0;31m'

# 默认设置
DEFAULT_SSH_PORT="22222"  # 设置一个安全的默认值，或者留空强制输入
SSH_PORT=""
NEW_USER=""
NEW_USER_PASSWORD=""
SSH_PUBLIC_KEY=""

# 帮助信息
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -u <user>      New Username"
    echo "  -p <password>  New Password (Not recommended via flag for security)"
    echo "  -k <key>       SSH Public Key (Must be quoted)"
    echo "  -P <port>      SSH Port (Default: $DEFAULT_SSH_PORT)"
    echo "  -h             Show help"
    exit 1
}

# 1. 解析命令行参数 (如果你想通过命令直接传参)
while getopts "u:p:k:P:h" opt; do
  case $opt in
    u) NEW_USER="$OPTARG" ;;
    p) NEW_USER_PASSWORD="$OPTARG" ;;
    k) SSH_PUBLIC_KEY="$OPTARG" ;;
    P) SSH_PORT="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# 2. 交互式输入 (如果参数未提供，则询问)

echo -e "${GREEN}=== Setup Initialization ===${NC}"

# --- 用户名 ---
if [[ -z "$NEW_USER" ]]; then
    read -p "Enter new username: " NEW_USER
fi

# --- 密码 (输入不可见) ---
if [[ -z "$NEW_USER_PASSWORD" ]]; then
    while [[ -z "$NEW_USER_PASSWORD" ]]; do
        read -s -p "Enter new password: " NEW_USER_PASSWORD
        echo "" # Newline
    done
fi

# --- SSH 端口 ---
if [[ -z "$SSH_PORT" ]]; then
    read -p "Enter SSH Port [Press Enter for default $DEFAULT_SSH_PORT]: " input_port
    SSH_PORT="${input_port:-$DEFAULT_SSH_PORT}"
fi

# --- SSH 公钥 ---
if [[ -z "$SSH_PUBLIC_KEY" ]]; then
    echo -e "${YELLOW}Paste your full SSH Public Key (starting with ssh-ed25519 or ssh-rsa):${NC}"
    read -r SSH_PUBLIC_KEY
fi

# 3. 最终安全检查
if [[ -z "$NEW_USER" || -z "$NEW_USER_PASSWORD" || -z "$SSH_PUBLIC_KEY" ]]; then
    echo -e "${RED}Error: Username, Password, and Public Key are required. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}Configuration ready. Starting hardening process in 3 seconds...${NC}"
sleep 3

# --- 脚本初始化 ---

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

set -u
# 注意:已移除某些特定命令中的“set -e”指令,以便手动处理错误,但通常情况下,我们希望捕获所有故障。
set -o pipefail

# 捕获错误
trap 'echo "Error: Command failed at line $LINENO. Aborting."; exit 1' ERR

export DEBIAN_FRONTEND=noninteractive

# --- 主要逻辑 ---

# 1. 系统初始化(根据apt的设计,该过程具有幂等性)
system_init() {
    echo -e "${YELLOW}[1/4] Installing/Updating essential packages...${NC}"
    
    # 请务必更新列表,以确保我们以后运行时能够获取最新版本。
    apt-get update -qq
    
    # 直接安装。Apt 会自动处理“已安装”的逻辑。
    # 添加 iptables-persistent 是为了确保以后需要时可以明确禁用它。
    echo -e "${BLUE}Ensuring packages are installed...${NC}"
    apt-get install -y --no-install-recommends sudo ufw openssh-server
}

# 2. 用户配置(幂等操作:创建或更新)
configure_user() {
    echo -e "${YELLOW}[2/4] Configuring administrative user '$NEW_USER'...${NC}"

    # 检查用户是否存在
    if id "$NEW_USER" &>/dev/null; then
        echo -e "${BLUE}User $NEW_USER already exists. Proceeding to update configuration.${NC}"
    else
        echo -e "${BLUE}Creating user $NEW_USER...${NC}"
        adduser --disabled-password --gecos "" "$NEW_USER"
    fi

    # 幂等性:始终更新密码,无论用户是否存在。
    echo -e "${BLUE}Updating password for $NEW_USER...${NC}"
    echo "$NEW_USER:$NEW_USER_PASSWORD" | chpasswd

    # 幂等性:始终确保用户属于 sudo 用户组。
    if ! groups "$NEW_USER" | grep -q '\bsudo\b'; then
        echo -e "${BLUE}Adding $NEW_USER to sudo group...${NC}"
        usermod -aG sudo "$NEW_USER"
    else
        echo -e "${BLUE}User $NEW_USER is already in sudo group.${NC}"
    fi
}

# 3. Firewall Configuration (Idempotent: Reset & Re-apply)
configure_firewall_ufw() {
    echo -e "${YELLOW}[4/4] Configuring UFW firewall (Idempotent Reset)...${NC}"

    # IDEMPOTENCY: Detect and stop conflicting firewalls
    # Stop nftables if it exists/runs
    if systemctl list-unit-files | grep -q nftables; then
        echo -e "${BLUE}Stopping and disabling nftables to prevent conflicts...${NC}"
        systemctl stop nftables &>/dev/null || true
        systemctl disable nftables &>/dev/null || true
    fi
    
    # Stop iptables-persistent / netfilter-persistent if installed
    if systemctl list-unit-files | grep -q netfilter-persistent; then
         echo -e "${BLUE}Stopping netfilter-persistent...${NC}"
         systemctl stop netfilter-persistent &>/dev/null || true
         systemctl disable netfilter-persistent &>/dev/null || true
    fi

    # IDEMPOTENCY: Reset UFW to clear old rules (e.g. if port changed)
    # --force prevents confirmation prompt
    echo -e "${BLUE}Resetting UFW to default state...${NC}"
    ufw --force reset

    # Re-apply configuration
    echo -e "${BLUE}Setting deny incoming / allow outgoing...${NC}"
    ufw default deny incoming
    ufw default allow outgoing

    echo -e "${BLUE}Allowing SSH port $SSH_PORT...${NC}"
    ufw allow "${SSH_PORT}/tcp"

    echo -e "${BLUE}Enabling UFW...${NC}"
    ufw --force enable

    # Ensure service is running
    systemctl enable ufw
    systemctl start ufw
    
    echo -e "${GREEN}UFW Rules Refreshed.${NC}"
}

# 4. SSH 配置和密钥(幂等操作:备份并覆盖)
configure_ssh() {
    echo -e "${YELLOW}[3/4] Hardening SSH and configuring Keys...${NC}"

    local user_home="/home/$NEW_USER"
    local user_ssh_dir="$user_home/.ssh"
    local auth_keys_file="$user_ssh_dir/authorized_keys"
    local ssh_config_file="/etc/ssh/sshd_config"
    local timestamp=$(date +%Y%m%d_%H%M%S)

    # --- SSH KEYS HANDLING ---
    echo -e "${BLUE}Configuring SSH keys...${NC}"
    mkdir -p "$user_ssh_dir"

    # IDEMPOTENCY: Backup existing keys if they exist, but don't fail if they don't
    if [ -f "$auth_keys_file" ]; then
        echo -e "${BLUE}Backing up existing authorized_keys to authorized_keys.bak.$timestamp...${NC}"
        cp "$auth_keys_file" "$auth_keys_file.bak.$timestamp"
    fi

    # IDEMPOTENCY: Overwrite (>) the key file to ensure exact match with config
    echo -e "${BLUE}Overwriting authorized_keys with provided key...${NC}"
    echo "$SSH_PUBLIC_KEY" > "$auth_keys_file"

    # Fix Permissions (Always apply to ensure security)
    chmod 700 "$user_ssh_dir"
    chmod 600 "$auth_keys_file"
    chown -R "$NEW_USER:$NEW_USER" "$user_ssh_dir"

    # --- SSHD CONFIG HANDLING ---
    echo -e "${BLUE}Configuring sshd_config...${NC}"
    
    # IDEMPOTENCY: Backup existing config
    if [ -f "$ssh_config_file" ]; then
        echo -e "${BLUE}Backing up sshd_config to sshd_config.bak.$timestamp...${NC}"
        cp "$ssh_config_file" "$ssh_config_file.bak.$timestamp"
    fi

    # IDEMPOTENCY: Overwrite config entirely
    cat > "$ssh_config_file" << EOF
# Hardened SSH Configuration (Applied: $timestamp)

# Include Modular Configs
# 这允许系统包管理器(如cloud-init)放置特定配置。
Include /etc/ssh/sshd_config.d/*.conf

# Port
Port ${SSH_PORT}

# Strong Crypto Algorithms (进阶强化:仅允许强加密算法)
# 警告:这可能会导致非常旧的客户端(如Putty < 0.70, 旧版WinSCP)无法连接
# Key Exchange Algorithms (删除了 SHA1 和 弱 Diffie-Hellman)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

# Ciphers (仅保留 GCM 和 ChaCha20，禁用 CBC 和 weak CTR)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com

# MACs (消息验证码，强制使用 Encrypt-then-MAC)
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
UsePAM yes

# Access Control
AllowUsers ${NEW_USER}

# Security Settings
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
StrictModes yes

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Disable unwanted features
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*

# File Transfer (CRITICAL FIX)
Subsystem sftp internal-sftp
EOF

# Verify SSH configuration before restarting
    echo -e "${BLUE}Verifying sshd_config syntax...${NC}"
    if /usr/sbin/sshd -t -f "$ssh_config_file"; then
        echo -e "${GREEN}Syntax check passed. Restarting SSH service...${NC}"
        # 只有检查通过才重启
        if systemctl is-active --quiet ssh; then
            systemctl restart ssh
        else
            systemctl start ssh
        fi
    else
        echo -e "${RED}CRITICAL ERROR: sshd_config syntax check failed!${NC}"
        echo -e "${RED}Changes have NOT been applied to the running service to prevent lockout.${NC}"
        echo -e "${YELLOW}Please check $ssh_config_file manually. Restoring from backup is recommended.${NC}"
        # 我们可以选择在这里尝试自动恢复备份，或者直接退出让用户处理
        # 简单的做法是直接退出，保证当前运行的 SSH 进程不被杀死
        exit 1
    fi
}

# --- Main Execution ---
main() {
    echo -e "\n${GREEN}=== Starting Idempotent Security Setup ===${NC}"
    
    system_init
    configure_user
    configure_firewall_ufw
    configure_ssh

    echo -e "\n${GREEN}--- Setup Complete! ---${NC}\n"
    echo -e "${YELLOW}NOTE: Because this script is idempotent:${NC}"
    echo " - SSH Config was overwritten (backup saved)."
    echo " - SSH Keys were overwritten (backup saved)."
    echo " - UFW rules were reset and re-applied."
    echo ""
    echo -e "New Login Command:"
    echo -e "${BLUE}ssh -p $SSH_PORT -i /path/to/private_key $NEW_USER@<server_ip>${NC}"
    echo ""
}

main

exit 0
