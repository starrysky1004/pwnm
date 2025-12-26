#!/usr/bin/env bash
# Author: starrysky
# Contributor： Rimuawa
# Description: Auto setup pwn environment

# Source common.sh for color output functions if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/common.sh" ]; then
	source "$SCRIPT_DIR/common.sh"
else
	# Fallback color definitions
	psuccess() { echo -e "\033[32m✅ $*\033[0m"; }
	pinfo() { echo -e "\033[35mℹ️  $*\033[0m"; }
	pwarn() { echo -e "\033[33m⚠️  $*\033[0m"; }
	perror() { echo -e "\033[31m❌ $*\033[0m" 1>&2; }
fi

# Progress bar variables
TOTAL_STEPS=12
CURRENT_STEP=0
PROGRESS_PID=""
PROGRESS_FILE="/tmp/pwnm_progress_$$"

# Background progress bar updater
progress_bar_daemon() {
	local progress_file="$1"

	while true; do
		# Read current step from file
		local current_step=0
		if [ -f "$progress_file" ]; then
			current_step=$(cat "$progress_file" 2>/dev/null || echo 0)
		fi

		local percent=$((current_step * 100 / TOTAL_STEPS))
		local term_width=$(tput cols 2>/dev/null || echo 80)
		local total_lines=$(tput lines 2>/dev/null || echo 24)
		local last_line=$((total_lines - 1))
		local bar_width=$((term_width - 10))

		if [ $bar_width -lt 60 ]; then
			bar_width=60
		fi

		local filled=$((bar_width * current_step / TOTAL_STEPS))
		local empty=$((bar_width - filled))

		# Build progress bar
		local bar=""
		for ((i=0; i<filled; i++)); do
			bar="${bar}━"
		done

		# Save cursor position, move to last line
		# Using direct ANSI escape codes to ensure it works
		printf "\033[s"
		printf "\033[%d;0H" "$total_lines"

		# Clear line and print progress bar with background
		printf "\033[K\033[48;2;20;20;20m"

		if [ $filled -lt $bar_width ]; then
			printf "\033[38;2;255;105;180m%s\033[0m\033[48;2;20;20;20m" "$bar"
			printf "\033[38;2;255;105;180m♥\033[0m\033[48;2;20;20;20m"
			for ((i=0; i<empty-1; i++)); do
				printf "\033[38;2;100;100;100m━\033[0m\033[48;2;20;20;20m"
			done
		else
			printf "\033[38;2;255;105;180m%s♥\033[0m\033[48;2;20;20;20m" "$bar"
		fi

		printf " \033[38;2;255;150;210m%3d%%\033[0m" "$percent"

		# Restore cursor position
		printf "\033[u"

		sleep 0.1
	done
}

# Update progress step
update_progress() {
	CURRENT_STEP=$((CURRENT_STEP + 1))
	echo "$CURRENT_STEP" > "$PROGRESS_FILE"
}

# Print section banner
print_section() {
	local title="$1"

	echo ""
	echo -e "\033[38;2;255;105;180m╔════════════════════════════════════════╗\033[0m"
	echo -e "\033[38;2;255;130;200m║  $title\033[0m"
	echo -e "\033[38;2;255;105;180m╚════════════════════════════════════════╝\033[0m"
	echo ""
}

# Step 1: Install necessary packages
pwnm_setup_step1_packages() {
	print_section "🔧 安装必要环境"

	cd ~

	pinfo "→ 开始安装系统依赖包..."

	local packages=(
		tzdata vim libxml2-dev libxslt-dev libmysqlclient-dev
		libsqlite3-dev zlib1g-dev python2-dev python3-pip
		libffi-dev libssl-dev wget curl gcc clang make zip
		build-essential libncursesw5-dev libgdbm-dev libc6-dev
		tk-dev openssl virtualenv git proxychains4 ruby-dev net-tools
	)

	# Install packages one by one with progress feedback
	for pkg in "${packages[@]}"; do
		pinfo "   正在安装: $pkg"
		sudo apt install -y "$pkg" > /dev/null 2>&1 || pwarn "   $pkg 安装失败，继续下一个..."
	done
	psuccess "  ✓ 系统依赖包就绪"
	update_progress

	# Install setuptools for Python2
	pinfo "→ 安装 Python2 setuptools..."
	wget --no-check-certificate -q -O setuptools-36.6.1.zip https://mirrors.aliyun.com/pypi/packages/56/a0/4dfcc515b1b993286a64b9ab62562f09e6ed2d09288909aee1efdb9dde16/setuptools-36.6.1.zip 2>/dev/null || wget -q -O setuptools-36.6.1.zip https://mirrors.aliyun.com/pypi/packages/56/a0/4dfcc515b1b993286a64b9ab62562f09e6ed2d09288909aee1efdb9dde16/setuptools-36.6.1.zip
	unzip -q setuptools-36.6.1.zip
	cd setuptools-36.6.1
	sudo python2 setup.py install > /dev/null 2>&1
	cd ../
	sudo rm -rf setuptools-36.6.1 setuptools-36.6.1.zip
	psuccess "  ✓ Python2 setuptools 就绪"
	update_progress

	# Install setuptools for Python3
	pinfo "→ 安装 Python3 setuptools..."
	wget --no-check-certificate -q -O setuptools-65.4.1.tar.gz https://mirrors.aliyun.com/pypi/packages/03/c9/7b050ea4cc4144d0328f15e0b43c839e759c6c639370a3b932ecf4c6358f/setuptools-65.4.1.tar.gz 2>/dev/null || wget -q -O setuptools-65.4.1.tar.gz https://mirrors.aliyun.com/pypi/packages/03/c9/7b050ea4cc4144d0328f15e0b43c839e759c6c639370a3b932ecf4c6358f/setuptools-65.4.1.tar.gz
	tar -zxf setuptools-65.4.1.tar.gz > /dev/null 2>&1
	cd setuptools-65.4.1
	sudo python3 setup.py install > /dev/null 2>&1
	cd ../
	sudo rm -rf setuptools-65.4.1 setuptools-65.4.1.tar.gz
	psuccess "  ✓ Python3 setuptools 就绪"
	update_progress

	# Install pip
	pinfo "→ 安装 pip 包管理器..."
	wget --no-check-certificate -q -O pip-20.3.4.tar.gz https://mirrors.aliyun.com/pypi/packages/53/7f/55721ad0501a9076dbc354cc8c63ffc2d6f1ef360f49ad0fbcce19d68538/pip-20.3.4.tar.gz 2>/dev/null || wget -q -O pip-20.3.4.tar.gz https://mirrors.aliyun.com/pypi/packages/53/7f/55721ad0501a9076dbc354cc8c63ffc2d6f1ef360f49ad0fbcce19d68538/pip-20.3.4.tar.gz
	tar -zxf pip-20.3.4.tar.gz > /dev/null 2>&1
	cd pip-20.3.4
	sudo python2 setup.py install > /dev/null 2>&1
	sudo python3 setup.py install > /dev/null 2>&1
	cd ../
	sudo rm -rf pip-20.3.4 pip-20.3.4.tar.gz
	psuccess "  ✓ pip 就绪"
	update_progress

	# Configure pip mirror
	pinfo "→ 配置 pip 阿里云镜像源..."
	sudo pip2 config set global.index-url https://mirrors.aliyun.com/pypi/simple > /dev/null 2>&1
	sudo pip3 config set global.index-url https://mirrors.aliyun.com/pypi/simple > /dev/null 2>&1

	# Upgrade pip
	pinfo "→ 升级 pip 到最新版本..."
	sudo python2 -m pip install --upgrade pip > /dev/null 2>&1
	sudo python3 -m pip install --upgrade pip > /dev/null 2>&1
	pip3 install --upgrade pip > /dev/null 2>&1

	sudo pip2 install pathlib2 > /dev/null 2>&1

	pip install z3

	psuccess "✓ 必要环境配置完成"
	update_progress
}

# Step 2: Install pwntools
pwnm_setup_step2_pwntools() {
	print_section "🐍 安装 pwntools"

	pinfo "→ 正在安装 pwntools (Python2 & Python3)..."
	sudo python2 -m pip install --upgrade pwntools > /dev/null 2>&1 || pwarn "Python2 pwntools 安装失败"
	sudo python3 -m pip install --upgrade pwntools > /dev/null 2>&1 || pwarn "Python3 pwntools 安装失败"

	psuccess "✓ pwntools 安装完成"
	update_progress
}

# Step 3: Install pwndbg + Pwngdb
pwnm_setup_step3_pwndbg() {
	print_section "🐛 安装调试工具 pwndbg & Pwngdb"

	cd ~

	pinfo "→ 下载 pwnenv.zip..."
	wget -q https://starrysky1004.github.io/pwnenv.zip || { perror "下载 pwnenv.zip 失败"; return 1; }

	pinfo "→ 解压文件..."
	unzip -q pwnenv.zip
	rm pwnenv.zip

	# Check OS version
	local os_version=$(lsb_release -rs 2>/dev/null || echo "unknown")

	if [ "$os_version" != "20.04" ]; then
		# Remove existing pwndbg if present
		if [ -d "pwndbg" ]; then
			sudo rm -rf pwndbg
		fi

		# Clone fresh pwndbg from official repo
		pinfo "→ 克隆 pwndbg 官方仓库..."
		git clone -q https://github.com/pwndbg/pwndbg 2>/dev/null || { perror "克隆 pwndbg 失败"; return 1; }
	fi

	pinfo "→ 安装 pwndbg..."
	cd pwndbg
	./setup.sh > /dev/null 2>&1 || { perror "pwndbg 安装失败"; return 1; }

	pinfo "→ 配置 Pwngdb..."
	cd ~/

	# Create new .gdbinit with correct configuration
	cat > ~/.gdbinit <<'EOF'
source ~/pwndbg/gdbinit.py
source ~/Pwngdb/pwngdb.py
source ~/Pwngdb/angelheap/gdbinit.py

define hook-run
python
import angelheap
angelheap.init_angelheap()
end
end
EOF

	psuccess "✓ 调试工具配置完成"
	update_progress
}

# Step 4: Install patchelf
pwnm_setup_step4_patchelf() {
	print_section "🔨 安装 patchelf"

	pinfo "→ 正在安装 patchelf..."
	sudo apt install patchelf -y > /dev/null 2>&1 || { perror "patchelf 安装失败"; return 1; }

	psuccess "✓ patchelf 安装完成"
	update_progress
}

# Step 5: Install glibc-all-in-one
pwnm_setup_step5_glibc() {
	print_section "📚 安装 glibc-all-in-one"

	cd ~

	pinfo "→ 克隆 glibc-all-in-one 仓库..."
	git clone -q https://github.com/matrix1001/glibc-all-in-one.git 2>/dev/null || { perror "克隆失败"; return 1; }

	cd glibc-all-in-one
	pinfo "→ 更新 glibc 版本列表..."
	python3 update_list > /dev/null 2>&1 || pwarn "更新列表失败"

	psuccess "✓ glibc-all-in-one 安装完成"
	cd ~
	update_progress
}

# Step 6: Install ropper
pwnm_setup_step6_ropper() {
	print_section "⚙️  安装 ropper"

	pinfo "→ 安装 ropper 及其依赖..."
	sudo pip3 install capstone filebytes unicorn keystone-engine ropper > /dev/null 2>&1 || { perror "ropper 安装失败"; return 1; }

	psuccess "✓ ropper 安装完成"
	update_progress
}

# Step 7: Install qemu-system
pwnm_setup_step7_qemu() {
	print_section "💻 安装 qemu-system"

	pinfo "→ 正在安装 qemu-system..."
	sudo apt-get install qemu-system -y > /dev/null 2>&1 || { perror "qemu-system 安装失败"; return 1; }

	psuccess "✓ qemu-system 安装完成"
	update_progress
}

# Step 8: Install ROPgadget
pwnm_setup_step8_ropgadget() {
	print_section "🔗 安装 ROPgadget"

	pinfo "→ 正在安装 ROPgadget..."
	sudo -H python3 -m pip install ROPgadget > /dev/null 2>&1 || { perror "ROPgadget 安装失败"; return 1; }

	psuccess "✓ ROPgadget 安装完成"
	update_progress
}

# Step 9: Show one_gadget and seccomp-tools info
pwnm_setup_step9_optional() {
	print_section "💎 可选工具"

	pwarn "以下工具安装较慢且极可能失败，建议在空闲时间尝试安装：（必要工具）"
	echo ""
	pinfo "• one_gadget 安装命令："
	echo "  sudo gem install one_gadget"
	echo ""
	pinfo "• seccomp-tools 安装命令："
	echo "  sudo gem install seccomp-tools"
	echo ""
}

# Main setup function - runs all steps
pwnm_setup_env_all() {
	# Record start time
	local start_time=$(date +%s)

	# Reset progress
	CURRENT_STEP=0
	echo "0" > "$PROGRESS_FILE"

	# Clear screen first
	clear

	# Hide cursor for cleaner output
	tput civis

	# Set scrolling region to exclude last line (for progress bar)
	# Line numbers are 0-indexed for tput csr
	local total_lines=$(tput lines)
	local last_line=$((total_lines - 1))
	local scroll_end=$((total_lines - 2))

	# Set scrolling region: lines 0 to (total_lines - 2)
	# This reserves the last line for the progress bar
	tput csr 0 $scroll_end

	# Move cursor to top
	tput cup 0 0

	echo -e "\033[38;2;255;105;180m╔═══════════════════════════════════╗\033[0m"
	echo -e "\033[38;2;255;130;200m║  ▄▄▄▄   ▄     ▄  ▄   ▄  ▄     ▄   ║\033[0m"
	echo -e "\033[38;2;255;150;210m║  █▀▀█▄  █     █  █▀▄ █  █▀▄ ▄▀█   ║\033[0m"
	echo -e "\033[38;2;255;170;220m║  █▄▄█▀  █  █  █  █  ▀█  █  ▀  █   ║\033[0m"
	echo -e "\033[38;2;255;190;230m║  █      ▀▄▄█▄▄▀  █   █  █     █   ║\033[0m"
	echo -e "\033[38;2;230;200;255m║                                   ║\033[0m"
	echo -e "\033[38;2;230;200;255m║         pwn env setup ❤           ║\033[0m"
	echo -e "\033[38;2;255;105;180m╚═══════════════════════════════════╝\033[0m"

	pinfo "开始配置 PWN 环境...(预计耗时15-20分钟)"

	# Start background progress bar daemon
	progress_bar_daemon "$PROGRESS_FILE" &
	PROGRESS_PID=$!

	sleep 2

	# Run all steps
	pwnm_setup_step1_packages || { kill $PROGRESS_PID 2>/dev/null; return 1; }
	pwnm_setup_step2_pwntools || { kill $PROGRESS_PID 2>/dev/null; return 1; }
	pwnm_setup_step3_pwndbg || { kill $PROGRESS_PID 2>/dev/null; return 1; }
	pwnm_setup_step4_patchelf || { kill $PROGRESS_PID 2>/dev/null; return 1; }
	pwnm_setup_step5_glibc || { kill $PROGRESS_PID 2>/dev/null; return 1; }
	pwnm_setup_step6_ropper || { kill $PROGRESS_PID 2>/dev/null; return 1; }
	pwnm_setup_step7_qemu || { kill $PROGRESS_PID 2>/dev/null; return 1; }
	pwnm_setup_step8_ropgadget || { kill $PROGRESS_PID 2>/dev/null; return 1; }
	pwnm_setup_step9_optional

	# Stop progress bar daemon
	kill $PROGRESS_PID 2>/dev/null
	wait $PROGRESS_PID 2>/dev/null

	# Clean up progress file
	rm -f "$PROGRESS_FILE"

	# Clear the progress bar line completely
	local total_lines=$(tput lines)
	tput cup $total_lines 0
	printf "\033[K"

	# Reset scrolling region to full screen
	tput csr 0 $total_lines

	# Move cursor back to normal position
	tput cup $((total_lines - 1)) 0

	# Show cursor again
	tput cnorm

	# Final message
	echo ""
	echo ""
	echo -e "\033[38;2;255;105;180m╔═══════════════════════════════════════════════╗\033[0m"
	echo -e "\033[38;2;255;130;200m║                                               ║\033[0m"
	echo -e "\033[38;2;255;150;210m║          🎉  环境配置完成！  🎉               ║\033[0m"
	echo -e "\033[38;2;255;130;200m║                                               ║\033[0m"
	echo -e "\033[38;2;255;105;180m╠═══════════════════════════════════════════════╣\033[0m"
	echo -e "\033[38;2;200;220;255m║                                               ║\033[0m"
	echo -e "\033[38;2;200;220;255m║   已安装工具列表：                            ║\033[0m"
	echo -e "\033[38;2;200;220;255m║                                               ║\033[0m"
	echo -e "\033[38;2;180;230;255m║     ✓  pwntools (Python2/3)                   ║\033[0m"
	echo -e "\033[38;2;180;230;255m║     ✓  pwndbg + Pwngdb                        ║\033[0m"
	echo -e "\033[38;2;180;230;255m║     ✓  patchelf                               ║\033[0m"
	echo -e "\033[38;2;180;230;255m║     ✓  glibc-all-in-one                       ║\033[0m"
	echo -e "\033[38;2;180;230;255m║     ✓  ropper                                 ║\033[0m"
	echo -e "\033[38;2;180;230;255m║     ✓  qemu-system                            ║\033[0m"
	echo -e "\033[38;2;180;230;255m║     ✓  ROPgadget                              ║\033[0m"
	echo -e "\033[38;2;200;220;255m║                                               ║\033[0m"
	echo -e "\033[38;2;255;105;180m╚═══════════════════════════════════════════════╝\033[0m"
	echo ""

	# Calculate and display elapsed time
	local end_time=$(date +%s)
	local elapsed=$((end_time - start_time))
	local minutes=$((elapsed / 60))
	local seconds=$((elapsed % 60))

	if [ $minutes -gt 0 ]; then
		pinfo "总耗时：${minutes} 分 ${seconds} 秒"
	else
		pinfo "总耗时：${seconds} 秒"
	fi

	psuccess "所有配置已完成！现在可以开始 PWN 之旅啦 ♥"
}

# If script is executed directly, run all setup
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	pwnm_setup_env_all
fi
