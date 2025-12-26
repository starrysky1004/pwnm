#!/usr/bin/env bash
# Author: starrysky
# Contributor： Rimuawa
# Description: Common library for pwnm

# Color/format helpers (auto-disable on unsupported terminals)
PWNM_COLOR_RESET="\033[0m"
PWNM_COLOR_BLUE="\033[34m"
PWNM_COLOR_GREEN="\033[32m"
PWNM_COLOR_YELLOW="\033[33m"
PWNM_COLOR_RED="\033[31m"
PWNM_COLOR_MAGENTA="\033[35m"

PWNM_HOME="$HOME/.pwnm"
PWNM_CONF="$PWNM_HOME/config"
PWNM_INDEX="$PWNM_HOME/index.tsv"

# Resolve mkdir binary for robustness in various shells
MKDIR_BIN="${MKDIR_BIN:-$(command -v mkdir 2>/dev/null || echo /bin/mkdir)}"

# Detect ANSI color and UTF-8 emoji support
pwnm_init_colors(){
	# Disable colors if not a TTY or TERM is dumb
	if [ ! -t 1 ] || [ "${TERM:-}" = "dumb" ]; then
		PWNM_COLOR_RESET=""; PWNM_COLOR_BLUE=""; PWNM_COLOR_GREEN=""; PWNM_COLOR_YELLOW=""; PWNM_COLOR_RED=""; PWNM_COLOR_MAGENTA=""
	fi
}

pwnm_supports_emoji(){
	# Basic heuristic: allow emoji only in UTF-8 locales
	case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
		*UTF-8*|*utf8*) return 0;;
		*) return 1;;
	esac
}

pemoji(){
	# Usage: pemoji ok|warn|err|info -> prints emoji or empty if unsupported
	local k="$1"
	if pwnm_supports_emoji; then
		case "$k" in
			ok)   printf "✅  ";;
			warn) printf "⚠️  ";;
			err)  printf "❌  ";;
			info) printf "ℹ️  ";;
			*)    printf "";;
		esac
	else
		printf ""
	fi
}

# Colored print helpers (emojis are safe-fallback)
pblue(){ echo -e "${PWNM_COLOR_BLUE}$*${PWNM_COLOR_RESET}"; }
psuccess(){ echo -e "${PWNM_COLOR_GREEN}$(pemoji ok)$*${PWNM_COLOR_RESET}"; }
pwarn(){ echo -e "${PWNM_COLOR_YELLOW}$(pemoji warn)$*${PWNM_COLOR_RESET}"; }
perror(){ echo -e "${PWNM_COLOR_RED}$(pemoji err)$*${PWNM_COLOR_RESET}" 1>&2; }
pinfo(){ echo -e "${PWNM_COLOR_MAGENTA}$(pemoji info)$*${PWNM_COLOR_RESET}"; }

pwnm_init_colors

pwnm_tolower(){
	# Lowercase with tr; fallback to raw input
	local s="$1"
	if command -v tr >/dev/null 2>&1; then
		printf "%s" "$s" | tr '[:upper:]' '[:lower:]'
	else
		printf "%s" "$s"
	fi
}

pwnm_json_escape(){
	# Minimal JSON string escape: backslash, quote, newline, CR
	local s="$1"
	s="${s//\\/\\\\}"   # backslashes
	s="${s//\"/\\\"}"  # quotes
	s="${s//$'\n'/\\n}"   # newlines
	s="${s//$'\r'/}"       # carriage returns
	echo "$s"
}

pwnm_load_config(){
	$MKDIR_BIN -p "$PWNM_HOME" || true
	if [ -f "$PWNM_CONF" ]; then
		PWNM_ROOT="$(grep '^ROOT=' "$PWNM_CONF" | head -n1 | cut -d'=' -f2-)"
		GLIBC_ALL_IN_ONE="$(grep '^GLIBC=' "$PWNM_CONF" | head -n1 | cut -d'=' -f2-)"
	fi
}

pwnm_write_config(){
	local root="$1"; local glibc="$2"
	$MKDIR_BIN -p "$PWNM_HOME"
	{
		echo "ROOT=$root"
		[ -n "$glibc" ] && echo "GLIBC=$glibc" || echo "GLIBC="
	} > "$PWNM_CONF"
	PWNM_ROOT="$root"; GLIBC_ALL_IN_ONE="$glibc"
}

pwnm_open_folder(){
	local dir="$1"
	if command -v xdg-open >/dev/null 2>&1; then
		xdg-open "$dir" >/dev/null 2>&1 &
	elif command -v open >/dev/null 2>&1; then
		open "$dir" >/dev/null 2>&1 &
	elif command -v explorer.exe >/dev/null 2>&1; then
		if command -v wslpath >/dev/null 2>&1; then
			explorer.exe "$(wslpath -w "$dir")" >/dev/null 2>&1 &
		else
			explorer.exe "$dir" >/dev/null 2>&1 &
		fi
	elif command -v nautilus >/dev/null 2>&1; then
		nautilus "$dir" >/dev/null 2>&1 &
	elif command -v dolphin >/dev/null 2>&1; then
		dolphin "$dir" >/dev/null 2>&1 &
	elif command -v thunar >/dev/null 2>&1; then
		thunar "$dir" >/dev/null 2>&1 &
	elif command -v pcmanfm >/dev/null 2>&1; then
		pcmanfm "$dir" >/dev/null 2>&1 &
	fi
}

pwnm_open_vim_tab(){
	local file="$1"
	if command -v gnome-terminal >/dev/null 2>&1; then
		gnome-terminal --tab -- bash -lc "vim '$file'" &
	elif command -v konsole >/dev/null 2>&1; then
		konsole --new-tab -e bash -lc "vim '$file'" &
	elif command -v wt >/dev/null 2>&1; then
		wt new-tab --title pwnm -p "Command Prompt" bash -lc "vim '$file'" &
	elif command -v wt.exe >/dev/null 2>&1; then
		wt.exe new-tab --title pwnm -p "Command Prompt" bash -lc "vim '$file'" &
	elif command -v tmux >/dev/null 2>&1; then
		tmux new-window "vim '$file'" >/dev/null 2>&1 || tmux split-window "vim '$file'" &
	fi
}

pwnm_init_problem_meta(){
	local dir="$1"
	$MKDIR_BIN -p "$dir/.pwnm" || true
	local contest problem created_at
	contest="$(basename "$(dirname "$dir")")"
	problem="$(basename "$dir")"
	created_at="$(date +"%F %T")"
	# JSON-escape dynamic fields to avoid jq parse errors on Windows paths/backslashes
	local e_contest e_problem e_path
	e_contest="$(pwnm_json_escape "$contest")"
	e_problem="$(pwnm_json_escape "$problem")"
	e_path="$(pwnm_json_escape "$dir")"
	cat > "$dir/.pwnm/meta.json" <<-EOF
	{
		"contest": "$e_contest",
		"problem": "$e_problem",
		"workdir": "$e_path",
		"libc": "None",
		"arch": "None",
		"endian": "None",
		"protections": {"RELRO":"None","CANARY":"None","NX":"None","PIE":"None"},
		"tags": [],
		"created_at": "$created_at"
	}
	EOF
	pwnm_index_add "$contest" "$problem" "$dir" "None" "None" "None" "None" "None" "None" "None" "$created_at"
}

pwnm_update_meta_libc(){
	local dir="$1"; local ver="$2"
	local meta="$dir/.pwnm/meta.json"
	[ -f "$meta" ] || return 0
	sed -i.bak "s/\"libc\": \"[^\"]*\"/\"libc\": \"$ver\"/" "$meta" 2>/dev/null || true
	rm -f "$meta.bak" 2>/dev/null || true
	local contest problem created relro canary nx pie typ archv
	contest="$(basename "$(dirname "$dir")")"
	problem="$(basename "$dir")"
	created="$(sed -n 's/.*"created_at": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	relro=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"RELRO": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
	canary=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"CANARY": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
	nx=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"NX": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
	pie=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"PIE": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
	archv=$(sed -n 's/.*"arch": "\([^"]*\)".*/\1/p' "$meta" 2>/dev/null | head -n1)
	if command -v jq >/dev/null 2>&1; then
		typ="$(jq -r '(.tags // []) | join(",")' "$meta" 2>/dev/null)"
	else
		typ="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1 | sed 's/\"//g')"
	fi
	[ -z "$typ" ] && typ="None"
	pwnm_index_add "$contest" "$problem" "$dir" "$ver" "$archv" "$relro" "$canary" "$nx" "$pie" "$typ" "$created"
}

pwnm_mark_type(){
	[ "$#" -ge 1 ] || { perror "标签呢？！"; return 1; }
	local dir meta
	dir="$(pwd)"
	meta="$dir/.pwnm/meta.json"
	[ -f "$meta" ] || { perror "ww找不到它-> $meta"; return 1; }

	local contest problem created archv
	contest="$(basename "$(dirname "$dir")")"
	problem="$(basename "$dir")"

	# Ensure tags field exists
	if ! grep -q '"tags"' "$meta" 2>/dev/null; then
		# Insert tags field after protections
		awk '{
			print $0
			if ($0 ~ /"protections"[[:space:]]*:.*\}/) { print "\t\"tags\": []," }
		}' "$meta" > "$meta.tmp" && mv -f "$meta.tmp" "$meta"
	fi

	# Add tags to meta.json
	if command -v jq >/dev/null 2>&1; then
		local content tag
		content="$(cat "$meta")"
		for tag in "$@"; do
			content="$(printf '%s' "$content" | jq --arg t "$tag" '.tags = ((.tags // []) + [$t]) | .tags |= unique')"
		done
		printf '%s' "$content" > "$meta"
	else
		local raw list newlist t esc
		raw="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1)"
		list=",$raw,"
		newlist="$raw"
		for t in "$@"; do
			esc="$(pwnm_json_escape "$t")"
			if ! printf '%s' "$list" | grep -F -q ",\"$t\","; then
				if [ -n "$newlist" ]; then newlist="$newlist, \"$esc\""; else newlist="\"$esc\""; fi
				list="$list\"$t\","
			fi
		done
		sed -i.bak -E "s/\"tags\"[[:space:]]*:\[[^]]*\]/\"tags\": \[$newlist\]/" "$meta" 2>/dev/null || true
		rm -f "$meta.bak" 2>/dev/null || true
	fi

	# Update index
	local relro canary nx pie libc typ
	relro=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"RELRO": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
	canary=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"CANARY": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
	nx=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"NX": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
	pie=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"PIE": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
	libc=$(grep -o '"libc": "[^"]*"' "$meta" | cut -d'"' -f4)
	created="$(sed -n 's/.*"created_at": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	archv="$(sed -n 's/.*"arch": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"

	if command -v jq >/dev/null 2>&1; then
		typ="$(jq -r '(.tags // []) | join(",")' "$meta" 2>/dev/null)"
	else
		typ="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1 | sed 's/\"//g')"
	fi
	[ -z "$typ" ] && typ="None"

	pwnm_index_add "$contest" "$problem" "$dir" "$libc" "$archv" "$relro" "$canary" "$nx" "$pie" "$typ" "$created"
	psuccess "标签添加成功√: $*"
}

pwnm_index_add(){
	local contest="$1"; local problem="$2"; local workdir="$3"; local libc="$4"; local archv="$5"; local relro="$6"; local can="$7"; local nx="$8"; local pie="$9"; local typ="${10}"; local created="${11}"
	$MKDIR_BIN -p "$PWNM_HOME"
	if [ -f "$PWNM_INDEX" ]; then
		grep -v -F "$(printf "%s\t%s\t%s\t" "$contest" "$problem" "$workdir")" "$PWNM_INDEX" > "$PWNM_INDEX.tmp" 2>/dev/null || true
		mv -f "$PWNM_INDEX.tmp" "$PWNM_INDEX" 2>/dev/null || true
	fi
	printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
		"$contest" "$problem" "$workdir" "$libc" "$archv" "$relro" "$can" "$nx" "$pie" "$typ" "$created" >> "$PWNM_INDEX"
}

pwnm_index_to_lines(){
	[ -f "$PWNM_INDEX" ] || return 0
	# Display header without path column
	printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
			"比赛名称" "题目名称" "Libc" "Arch" \
			"RELRO" "Canary" "NX" "PIE" "题目类型" "创建时间"
	while IFS=$'\t' read -r contest problem workdir libc arch relro can nx pie typ created; do
		[ -z "$contest" ] && continue
		local endianv="" created_ym=""
		created_ym=$(printf "%s" "$created" | cut -c1-7)
		[ -z "$created_ym" ] && created_ym=$(printf "%s" "$created" | awk -F'-' '{print $1"-"$2}')
		# Output without workdir column
		printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
			"$contest" "$problem" "$libc" "$arch" \
			"$relro" "$can" "$nx" "$pie" "$typ" "$created_ym"
	done < "$PWNM_INDEX"
}

pwnm_index_to_lines_with_path(){
	[ -f "$PWNM_INDEX" ] || return 0
	# Internal function that includes path for lookup
	while IFS=$'\t' read -r contest problem workdir libc arch relro can nx pie typ created; do
		[ -z "$contest" ] && continue
		printf "%s\t%s\t%s\n" "$contest" "$problem" "$workdir"
	done < "$PWNM_INDEX"
}
    
# Commands implementation wrappers
pwnm_cmd_init(){
	pwnm_load_config

	# Ask if user wants auto setup
	echo ""
	pinfo "是否需要自动搭建 PWN 环境？(y/n)"
	read -r auto_setup
	auto_setup=$(pwnm_tolower "$auto_setup")

	# Ask for PWN challenge directory
	echo ""
	pinfo "请输入 PWN 题目存储路径 (直接回车默认: ~/pwn_challenge):"
	read -r root_dir
	[ -z "$root_dir" ] && root_dir="$HOME/pwn_challenge"
	PWNM_ROOT="$root_dir"

	# Handle glibc path based on auto setup choice
	if [ "$auto_setup" = "y" ] || [ "$auto_setup" = "yes" ]; then
		# Auto setup: use default glibc path
		GLIBC_ALL_IN_ONE="$HOME/glibc-all-in-one"
	else
		# Manual setup: ask for glibc path and check if directory exists
		echo ""
		pinfo "请输入 glibc-all-in-one 路径 (直接回车默认: ~/glibc-all-in-one):"
		read -r glibc_dir
		[ -z "$glibc_dir" ] && glibc_dir="$HOME/glibc-all-in-one"

		# Check if the specified directory exists
		if [ ! -d "$glibc_dir" ]; then
			pwarn "指定的 glibc-all-in-one 目录不存在: $glibc_dir"
			pinfo "请确保该目录存在或选择自动搭建环境"
		fi

		GLIBC_ALL_IN_ONE="$glibc_dir"
	fi

	$MKDIR_BIN -p "$PWNM_ROOT" "$PWNM_HOME" "$PWNM_HOME/templates"

	# bring templates from current repo
	REPO_ROOT=$PWNM_DIR/templates
	[ -d "$REPO_ROOT" ] && cp -rf "$REPO_ROOT" "$PWNM_HOME/" 2>/dev/null || true

	pwnm_write_config "$PWNM_ROOT" "$GLIBC_ALL_IN_ONE"

	# Run auto setup if user chose to
	if [ "$auto_setup" = "y" ] || [ "$auto_setup" = "yes" ]; then
		echo ""
		pinfo "开始自动搭建 PWN 环境..."

		# Source and run setup_env
		local setup_script="$PWNM_DIR/lib/setup_env.sh"
		if [ -f "$setup_script" ]; then
			# Fix CRLF line endings if on Windows/WSL
			if command -v dos2unix >/dev/null 2>&1; then
				dos2unix "$setup_script" 2>/dev/null || true
			else
				# Fallback: use sed to remove carriage returns
				sed -i 's/\r$//' "$setup_script" 2>/dev/null || true
			fi

			source "$setup_script"
			pwnm_setup_env_all
		else
			perror "找不到环境搭建脚本: $setup_script"
		fi

		echo ""
	fi

	sleep 3

	pinfo "安装工具ing..."
	sudo apt update -y && sudo apt install -y jq fzf binutils

	# shell integration: add function shortcut (does not modify PATH)
	local src_line="source $PWNM_DIR/pwnm.sh"
	for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
		if [ -f "$rc" ]; then
			grep -F "$src_line" "$rc" >/dev/null 2>&1 || echo "$src_line" >> "$rc"
		fi
	done

	psuccess "初始化完成，输入 pwnm 查看用法喵~"
	echo "ROOT: $PWNM_ROOT"
	[ -n "$GLIBC_ALL_IN_ONE" ] && echo "GLIBC: $GLIBC_ALL_IN_ONE"
}

pwnm_cmd_contest_create(){
	local name="$1"; [ -z "$name" ] && perror "比赛名呢？！" && return 1
	local dir="$PWNM_ROOT/$name"
	[ -d "$dir" ] && { perror "比赛名重复，换个名字喵~"; return 1; }
	$MKDIR_BIN -p "$dir" && cd "$dir" || return 1
}

pwnm_cmd_contest_goto(){
	local name="$1"; [ -z "$name" ] && perror "比赛名呢？！" && return 1
	local dir="$PWNM_ROOT/$name"
	if [ -d "$dir" ]; then cd "$dir" && psuccess "进入: $dir" && return 0; fi
	local match; match=$(ls -1 "$PWNM_ROOT" 2>/dev/null | grep -i "$name" | head -n1)
	[ -n "$match" ] && cd "$PWNM_ROOT/$match" && psuccess "进入: $PWNM_ROOT/$match" || { perror "找不到找不到找不到！！"; return 1; }
}

pwnm_cmd_contest_list(){ ls "$PWNM_ROOT" 2>/dev/null || true; }

pwnm_cmd_new_problem(){
	local name="$1"; shift || true; [ -z "$name" ] && perror "题目名呢？！" && return 1
	local mode=""; while [ $# -gt 0 ]; do case "$1" in --awd) mode="awd";; --awdp) mode="awdp";; esac; shift || true; done
	local cwd="$(pwd)"; case "$cwd" in "$PWNM_ROOT"/*) :;; *) perror "要在比赛文件夹下创建题目o~ (位于 $PWNM_ROOT 下)"; return 1;; esac
	# forbid creating inside an existing problem directory; only under contest level
	local parent; parent="$(dirname "$cwd")"; if [ "$parent" != "$PWNM_ROOT" ]; then perror "禁止套娃！！！"; return 1; fi
	local dir="$cwd/$name"; [ -d "$dir" ] && { perror "这个题目已经创建过辣: $name"; return 1; }
	$MKDIR_BIN -p "$dir"
	[ -f "$PWNM_HOME/templates/exp.py" ] && cp -f "$PWNM_HOME/templates/exp.py" "$dir/exp.py"
	if [ "$mode" = "awd" ]; then
		[ -d "$PWNM_HOME/templates/AwdPwnPatcher" ] && cp -rf "$PWNM_HOME/templates/AwdPwnPatcher" "$dir/"
		[ -d "$PWNM_HOME/templates/awdpwn" ] && cp -rf "$PWNM_HOME/templates/awdpwn" "$dir/"
		pinfo "打补丁前记得备份原程序哟w"
	elif [ "$mode" = "awdp" ]; then
		# Prepare result directory
		[ -d "$PWNM_HOME/templates/result" ] && cp -rf "$PWNM_HOME/templates/result" "$dir/"
		# Copy AwdPwnPatcher
		[ -d "$PWNM_HOME/templates/AwdPwnPatcher" ] && cp -rf "$PWNM_HOME/templates/AwdPwnPatcher" "$dir/"
		pinfo "打补丁前记得备份原程序哟w"
	fi
	# enter the problem directory after creation
	cd "$dir" || return 1
	pwnm_open_folder "$dir"
	pwnm_open_vim_tab "$dir/exp.py"
	pwnm_init_problem_meta "$dir"
}

pwnm_cmd_checksec(){
    local file="$1"; [ -z "$file" ] && perror "文件名呢？！" && return 1
	[ ! -f "$file" ] && perror "是不是忘了放文件了吖⭐" && return 1
	command -v checksec >/dev/null 2>&1 || { perror "要先安装 checksec 才能用w"; return 1; }
	
	# Try old version first, then fallback to new version
	local output relro stack nx pie is_new_version=0
	output=$(checksec $file 2>&1)
	
	if echo "$output" | grep -q "Error: No option selected"; then
		# New version - use --file
		is_new_version=1
		output=$(checksec --file="$file" 2>&1)
		checksec --file="$file"
	else
		checksec $file
	fi
	
	# Extract protections based on version
	if [ "$is_new_version" = "1" ]; then
		local data_line
		data_line=$(echo "$output" | sed 's/.*FILE[[:space:]]*//')
		
		# Parse using double-space as field separator
		relro=$(echo "$data_line" | awk -F'  ' '{print $1}')
		stack=$(echo "$data_line" | awk -F'  ' '{print $3}')
		nx=$(echo "$data_line" | awk -F'  ' '{print $5}')
		pie=$(echo "$data_line" | awk -F'  ' '{print $6}')
	else
		# Old version: key-value format
		relro=$(echo "$output" | grep "RELRO:" | cut -d':' -f2- | xargs)
		stack=$(echo "$output" | grep "Stack:" | cut -d':' -f2- | xargs)
		nx=$(echo "$output" | grep "NX:" | cut -d':' -f2- | xargs)
		pie=$(echo "$output" | grep "PIE:" | cut -d':' -f2- | xargs)
	fi

	# Update meta.json for info output
    local dir meta
	dir="$(cd "$(dirname "$file")" && pwd)"
	meta="$dir/.pwnm/meta.json"
	[ -f "$meta" ] || pwnm_init_problem_meta "$dir"
	
	# Get arch and endian from file command
	local arch endian
	if command -v file >/dev/null 2>&1; then
		local file_output bits
		file_output=$(file -b "$file" 2>/dev/null)
		
		# Extract bits (32-bit or 64-bit)
		if echo "$file_output" | grep -q "64-bit"; then
			bits="64"
		elif echo "$file_output" | grep -q "32-bit"; then
			bits="32"
		else
			bits="unknown"
		fi
		
		# Extract endian (MSB=big, LSB=little)
		if echo "$file_output" | grep -q "MSB"; then
			endian="big"
		elif echo "$file_output" | grep -q "LSB"; then
			endian="little"
		else
			endian="unknown"
		fi
		
		# Extract architecture (between first and second comma)
		local raw_arch
		raw_arch=$(echo "$file_output" | awk -F',' '{print $2}' | xargs)
		
		# Map architecture names
		case "$raw_arch" in
			"x86-64"|"x86_64") arch="amd64" ;;
			"Intel 80386"|"i386") arch="i386" ;;
			*) 
				# For other archs, normalize to lowercase and append bit width
				arch=$(echo "$raw_arch" | tr '[:upper:]' '[:lower:]')
				# Append bits if not already present
				if ! echo "$arch" | grep -q "$bits"; then
					arch="${arch}${bits}"
				fi
				;;
		esac
	else
		arch="unknown"
		endian="unknown"
	fi

	# Update index.tsv to reflect latest protections/libc/tags
	local contest problem libc typ created
	contest="$(basename "$(dirname "$dir")")"
	problem="$(basename "$dir")"
	created="$(sed -n 's/.*"created_at": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	libc="$(sed -n 's/.*"libc": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"

	if command -v jq >/dev/null 2>&1; then
		typ="$(jq -r '(.tags // []) | join(",")' "$meta" 2>/dev/null)"
	else
		typ="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1 | sed 's/\"//g')"
	fi
	[ -z "$typ" ] && typ="None"

	pwnm_index_add "$contest" "$problem" "$dir" "$libc" "$arch" "$relro" "$stack" "$nx" "$pie" "$typ" "$created"

	# Update meta.json with new protections, arch, and endian
	if command -v jq >/dev/null 2>&1; then
		# Use jq for reliable JSON updates
		local updated_meta
		updated_meta=$(jq --arg relro "$relro" \
			--arg canary "$stack" \
			--arg nx "$nx" \
			--arg pie "$pie" \
			--arg arch "$arch" \
			--arg endian "$endian" \
			'.protections.RELRO = $relro |
			 .protections.CANARY = $canary |
			 .protections.NX = $nx |
			 .protections.PIE = $pie |
			 .arch = $arch |
			 .endian = $endian' "$meta" 2>/dev/null)
		if [ -n "$updated_meta" ]; then
			echo "$updated_meta" > "$meta"
		fi
	else
		# Fallback: use sed with flexible regex (handle both with/without spaces after colon)
		sed -i.bak -E "s/\"RELRO\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"RELRO\": \"${relro}\"/" "$meta" 2>/dev/null || true
		sed -i.bak -E "s/\"CANARY\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"CANARY\": \"${stack}\"/" "$meta" 2>/dev/null || true
		sed -i.bak -E "s/\"NX\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"NX\": \"${nx}\"/" "$meta" 2>/dev/null || true
		sed -i.bak -E "s/\"PIE\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"PIE\": \"${pie}\"/" "$meta" 2>/dev/null || true
		sed -i.bak -E "s/\"arch\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"arch\": \"${arch}\"/" "$meta" 2>/dev/null || true
		sed -i.bak -E "s/\"endian\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"endian\": \"${endian}\"/" "$meta" 2>/dev/null || true
		rm -f "$meta.bak" 2>/dev/null || true
	fi
	psuccess "已更新元信息 (info 可查看)"
	
	# Rename to pwn if needed
	local base
	base="$(basename "$file")"
	if [ "$base" != "pwn" ] && [ -f "$dir/$base" ]; then
		mv -f "$dir/$base" "$dir/pwn" && psuccess "已重命名为: $dir/pwn"
	fi

	# Grant execute permission to the binary
	chmod +x "$file" 2>/dev/null || true
}

pwnm_cmd_glibc(){
	local file="$1"; local binname="${2:-pwn}"
	[ -z "$file" ] && perror "文件名呢？！" && return 1
	[ ! -f "$file" ] && perror "是不是打错文件名了吖⭐" && return 1
	[ -z "$GLIBC_ALL_IN_ONE" ] || [ ! -d "$GLIBC_ALL_IN_ONE" ] && { perror "要先设置 glibc-all-in-one 路径w"; return 1; }

	# Check if binary is statically linked FIRST
    local file_info
    file_info=$(file -b "$binname" 2>/dev/null)
    if echo "$file_info" | grep "statically linked"; then
            perror "静态链接无法修改 libc"
            return 1
    fi

	local ver="" 
	ver=$(strings "$file" | grep -m1 "GNU C Library" | sed -n 's/.*GLIBC \([^)]*\)).*/\1/p')
	[ -z "$ver" ] && { perror "GLIBC 版本解析失败"; return 1; }
	pinfo "libc版本解析成功<(^-^)>: $ver"
	# Detect architecture using checksec preferred to get arch/bits/endian and use arch part for glibc naming
	local arch_dir="" file_out cs_out arch_line arch bits endian
	if command -v checksec >/dev/null 2>&1; then
		cs_out=$(checksec --file="$file" 2>/dev/null || true)
		arch_line=$(echo "$cs_out" | awk -F':' '/Arch:/ {gsub(/^ +| +$/,"", $2); print $2; exit}')
		# Example: amd64-64-little
		arch=$(echo "$arch_line" | awk -F'-' '{print $1}')
		bits=$(echo "$arch_line" | awk -F'-' '{print $2}')
		endian=$(echo "$arch_line" | awk -F'-' '{print $3}')
		[ "$arch" = "amd64" ] && arch_dir="amd64"
		[ "$arch" = "i386" ] && arch_dir="i386"
	fi
	if [ -z "$arch_dir" ] && command -v file >/dev/null 2>&1; then
		file_out=$(file -b "$file" 2>/dev/null)
		case "$file_out" in
			*"64-bit"*) arch_dir="amd64" ;;
			*"32-bit"*) arch_dir="i386" ;;
		esac
	fi
	[ -z "$arch_dir" ] && { perror "程序架构识别失败"; return 1; }

	# Locate matching glibc directory under libs/: version_arch, e.g., 2.31-0ubuntu9.17_amd64
	local cand
	cand="$GLIBC_ALL_IN_ONE/libs/${ver}_${arch_dir}"
	if [ ! -d "$cand" ]; then
		# case-insensitive fallback search
		cand=$(find "$GLIBC_ALL_IN_ONE/libs" -maxdepth 1 -type d -iname "${ver}_${arch_dir}" | head -n1)
	fi
	[ -z "$cand" ] && { perror "未找到匹配 libc (版本: $ver, 架构: $arch_dir)，该更新 glibc-all-in-one/libs 了噢"; return 1; }

	local dst libc_path ld_path; dst="$(pwd)"
	# Prefer libc.so.6, fallback to libc-*.so, under extracted libs path
	libc_path=$(find "$cand" -maxdepth 1 -type f -name "libc.so.6" | head -n1)
	[ -z "$libc_path" ] && libc_path=$(find "$cand" -maxdepth 3 -type f -name "libc-*.so" | head -n1)
	# ld variants
	ld_path=$(find "$cand" -maxdepth 1 -type f \( -name "ld-*.so" -o -name "ld-linux*.so*" \) | head -n1)

	local libc_base ld_base
	if [ -n "$libc_path" ]; then
		libc_base="$(basename "$libc_path")"
		cp -f "$libc_path" "$dst/$libc_base"
	else
		perror "找不到 libc"
		return 1
	fi
	if [ -n "$ld_path" ]; then
		ld_base="$(basename "$ld_path")"
		cp -f "$ld_path" "$dst/$ld_base"
	else
		perror "找不到 ld"
		return 1
	fi

	pwnm_update_meta_libc "$dst" "$ver"

	# Backup the binary file before patching
	local bin="$dst/$binname"; [ -f "$bin" ] || bin="$file"
	local bak_file="${bin}.bak"
	if [ -f "$bin" ] && [ ! -f "$bak_file" ]; then
		cp -f "$bin" "$bak_file"
		psuccess "已备份为: $bak_file"
	fi

	if [ -f "$bin" ] && command -v patchelf >/dev/null 2>&1; then
		# get original libc name from ldd output
		local orig_libc ldd_output libc_line
		ldd_output=$(ldd "$bin" 2>/dev/null)
		# Find the line containing "libc"
		libc_line=$(echo "$ldd_output" | grep "libc")

		if echo "$libc_line" | grep -q "/lib/"; then
			# If line contains "/lib/", use standard name
			orig_libc="libc.so.6"
		else
			# Extract libc path: from first character to first space (excluding the space)
			orig_libc=$(echo "$libc_line" | awk '{print $1}')
		fi

		if [ -n "$ld_base" ] && [ -f "$dst/$ld_base" ]; then
			patchelf --set-interpreter "./$ld_base" "$bin" 2>/dev/null || true
		fi
		if [ -n "$libc_base" ] && [ -f "$dst/$libc_base" ] && [ -n "$orig_libc" ]; then
			# Prefer direct local path to avoid system lookup precedence issues
			patchelf --replace-needed "$orig_libc" "./$libc_base" "$bin" 2>/dev/null || true
		fi
		chmod 777 "$bin" 2>/dev/null || true
		[ -n "$libc_base" ] && [ -f "$dst/$libc_base" ] && chmod 777 "$dst/$libc_base" 2>/dev/null || true
		[ -n "$ld_base" ] && [ -f "$dst/$ld_base" ] && chmod 777 "$dst/$ld_base" 2>/dev/null || true
		psuccess "成功替换 pwn 文件 libc/ld √"
		# Print summary for troubleshooting
		local interp needed rpath
		interp=$(patchelf --print-interpreter "$bin" 2>/dev/null || true)
		pinfo "Interpreter: ${interp:-unknown}"
		pinfo "Needed: $(patchelf --print-needed "$bin" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
		rpath=$(patchelf --print-rpath "$bin" 2>/dev/null || true)
		[ -z "$rpath" ] && rpath=$(readelf -d "$bin" 2>/dev/null | awk '/RPATH|RUNPATH/{print $0}')
	else
		pwarn "未找到 patchelf 或二进制不存在，已跳过替换"
	fi
}

pwnm_cmd_mark_type(){
	[ "$#" -eq 0 ] && perror "标签呢？！使用方法: pwnm t <tag1> 或 pwnm t <tag1> t <tag2>" && return 1

	local tags=()
	local current_tag=""

	# Parse arguments: 't' is the delimiter between tags
	while [ "$#" -gt 0 ]; do
		if [ "$1" = "t" ]; then
			# 't' found: save current tag if not empty
			if [ -n "$current_tag" ]; then
				tags+=("$current_tag")
				current_tag=""
			fi
			shift
		else
			# Regular word: append to current tag
			if [ -z "$current_tag" ]; then
				current_tag="$1"
			else
				current_tag="$current_tag $1"
			fi
			shift
		fi
	done

	# Don't forget the last tag
	if [ -n "$current_tag" ]; then
		tags+=("$current_tag")
	fi

	[ ${#tags[@]} -eq 0 ] && perror "标签呢？！" && return 1
	pwnm_mark_type "${tags[@]}"
}

pwnm_rebuild_index_from_meta(){
    # Incrementally rebuild index.tsv using index.state for tracking
    pwnm_load_config
    [ -z "$PWNM_ROOT" ] && { perror "未设置工作区路径"; return 1; }
    [ ! -d "$PWNM_ROOT" ] && { perror "工作区路径不存在: $PWNM_ROOT"; return 1; }

    local PWNM_STATE="$PWNM_HOME/index.state"
    local current_time=$(date +%s)
    local three_minutes_ago=$((current_time - 180))  # 180 seconds = 3 minutes

    # Check if index was modified within last 3 minutes
    if [ -f "$PWNM_INDEX" ]; then
        local index_mtime=$(stat -c %Y "$PWNM_INDEX" 2>/dev/null || stat -f %m "$PWNM_INDEX" 2>/dev/null || echo 0)
        if [ "$index_mtime" -gt "$three_minutes_ago" ]; then
            # Index is fresh, skip rebuild
            return 0
        fi
    fi

    pinfo "正在更新题目索引..."

    # Step 1: Build list of indexed files from current index.tsv
    declare -A indexed_files  # workdir -> 1
    declare -A indexed_entries  # workdir -> full_line
    if [ -f "$PWNM_INDEX" ]; then
        while IFS=$'\t' read -r contest problem workdir libc arch relro canary nx pie typ created; do
            [ -z "$contest" ] && continue
            local metafile="$workdir/.pwnm/meta.json"
            if [ -f "$metafile" ]; then
                indexed_files["$metafile"]=1
                indexed_entries["$workdir"]="$(printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" \
                    "$contest" "$problem" "$workdir" "$libc" "$arch" "$relro" "$canary" "$nx" "$pie" "$typ" "$created")"
            fi
        done < "$PWNM_INDEX"
    fi

    # Step 2: Find all meta.json files and determine which need processing
    local new_files=()

    while IFS= read -r metafile; do
        local workdir="$(dirname "$(dirname "$metafile")")"

        # Only process if it follows the expected structure
        if [[ "$workdir" == "$PWNM_ROOT"/*/* ]]; then
            # Add to new_files if not already indexed
            if [ "${indexed_files[$metafile]}" != "1" ]; then
                new_files+=("$metafile")
            fi
        fi
    done < <(find "$PWNM_ROOT" -type f -path "*/.pwnm/meta.json" 2>/dev/null)

    # Step 3: Process new files with jq in batch
    local tmpindex=$(mktemp)
    : > "$tmpindex"

    # First, copy existing indexed entries
    for workdir in "${!indexed_entries[@]}"; do
        echo "${indexed_entries[$workdir]}" >> "$tmpindex"
    done

    # Process new files
    if [ ${#new_files[@]} -gt 0 ]; then
        pinfo "处理 ${#new_files[@]} 个新增题目..."

        if command -v jq >/dev/null 2>&1; then
            # Process all new files with jq
            for metafile in "${new_files[@]}"; do
                local workdir="$(dirname "$(dirname "$metafile")")"
                local problem_dir="$(basename "$workdir")"
                local contest_dir="$(basename "$(dirname "$workdir")")"

                # Extract all fields at once with jq
                local json_data
                json_data=$(jq -r '
                    def safe_string(v; default): if v == null or v == "" then default else v end;
                    [
                        safe_string(.contest; ""),
                        safe_string(.problem; ""),
                        safe_string(.libc; "None"),
                        safe_string(.arch; "None"),
                        safe_string(.protections.RELRO; "None"),
                        safe_string(.protections.CANARY; "None"),
                        safe_string(.protections.NX; "None"),
                        safe_string(.protections.PIE; "None"),
                        (if .tags then (.tags | join(",")) else "None" end),
                        safe_string(.created_at; "")
                    ] | @tsv
                ' "$metafile" 2>/dev/null || echo "")

                if [ -n "$json_data" ]; then
                    IFS=$'\t' read -r contest problem libc archv relro canary nx pie typ created <<< "$json_data"

                    # Use folder names as fallback
                    [ -z "$contest" ] && contest="$contest_dir"
                    [ -z "$problem" ] && problem="$problem_dir"
                    [ -z "$created" ] && created="$(date +"%F %T")"

                    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
                        "$contest" "$problem" "$workdir" "$libc" "$archv" "$relro" "$canary" "$nx" "$pie" "$typ" "$created" >> "$tmpindex"
                fi
            done
        else
            # Fallback: read all files at once then parse
            for metafile in "${new_files[@]}"; do
                local workdir="$(dirname "$(dirname "$metafile")")"
                local problem_dir="$(basename "$workdir")"
                local contest_dir="$(basename "$(dirname "$workdir")")"

                # Read entire file once
                local content=$(cat "$metafile" 2>/dev/null)

                # Extract all fields at once
                local contest=$(echo "$content" | sed -n 's/.*"contest": "\([^"]*\)".*/\1/p' | head -n1)
                local problem=$(echo "$content" | sed -n 's/.*"problem": "\([^"]*\)".*/\1/p' | head -n1)
                local libc=$(echo "$content" | sed -n 's/.*"libc": "\([^"]*\)".*/\1/p' | head -n1)
                local archv=$(echo "$content" | sed -n 's/.*"arch": "\([^"]*\)".*/\1/p' | head -n1)
                local relro=$(echo "$content" | sed -n '/"protections"/,/}/ { s/^[[:space:]]*"RELRO": "\([^"]*\)".*/\1/p }' | head -n1)
                local canary=$(echo "$content" | sed -n '/"protections"/,/}/ { s/^[[:space:]]*"CANARY": "\([^"]*\)".*/\1/p }' | head -n1)
                local nx=$(echo "$content" | sed -n '/"protections"/,/}/ { s/^[[:space:]]*"NX": "\([^"]*\)".*/\1/p }' | head -n1)
                local pie=$(echo "$content" | sed -n '/"protections"/,/}/ { s/^[[:space:]]*"PIE": "\([^"]*\)".*/\1/p }' | head -n1)
                local created=$(echo "$content" | sed -n 's/.*"created_at": "\([^"]*\)".*/\1/p' | head -n1)
                local typ=$(echo "$content" | sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' | head -n1 | sed 's/\"//g')

                # Set defaults
                [ -z "$contest" ] && contest="$contest_dir"
                [ -z "$problem" ] && problem="$problem_dir"
                [ -z "$libc" ] && libc="None"
                [ -z "$archv" ] && archv="None"
                [ -z "$relro" ] && relro="None"
                [ -z "$canary" ] && canary="None"
                [ -z "$nx" ] && nx="None"
                [ -z "$pie" ] && pie="None"
                [ -z "$typ" ] && typ="None"
                [ -z "$created" ] && created="$(date +"%F %T")"

                printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
                    "$contest" "$problem" "$workdir" "$libc" "$archv" "$relro" "$canary" "$nx" "$pie" "$typ" "$created" >> "$tmpindex"
            done
        fi
    fi

    # Step 4: Sort and deduplicate, then update index.tsv
    if [ -f "$tmpindex" ] && [ -s "$tmpindex" ]; then
        sort -t$'\t' -k3,3 -u "$tmpindex" > "$PWNM_INDEX.tmp"
        mv -f "$PWNM_INDEX.tmp" "$PWNM_INDEX"

        # Step 5: Update index.state with just the timestamp (no need for file list)
        echo "$(date +%s)" > "$PWNM_STATE"

        local count=$(wc -l < "$PWNM_INDEX" 2>/dev/null || echo 0)
        if [ ${#new_files[@]} -gt 0 ]; then
            psuccess "索引更新完成，共 $count 个题目"
        fi
    else
        rm -f "$tmpindex" 2>/dev/null || true
    fi
}

pwnm_cmd_search_tui(){
    # Rebuild index from all meta.json files before searching
    pwnm_rebuild_index_from_meta

    if command -v fzf >/dev/null 2>&1; then
        local tmpfile=$(mktemp)
        local tmppath=$(mktemp)

        # Create display file without paths
        pwnm_index_to_lines > "$tmpfile"

        # Create path mapping file
        pwnm_index_to_lines_with_path > "$tmppath"

        # Show fzf with formatted columns
        sel=$(column -t -s $'\t' "$tmpfile" | fzf --ansi --multi --header-lines=1 --layout=reverse)
        [ -z "$sel" ] && { rm -f "$tmpfile" "$tmppath"; return 1; }

        # Extract contest and problem from selection
        local sel_contest=$(echo "$sel" | awk '{print $1}')
        local sel_problem=$(echo "$sel" | awk '{print $2}')

        # Find the workdir from the path mapping file
        local workdir
        workdir=$(awk -F$'\t' -v c="$sel_contest" -v p="$sel_problem" '$1==c && $2==p {print $3; exit}' "$tmppath")

        rm -f "$tmpfile" "$tmppath"

        [ -d "$workdir" ] && cd "$workdir"
        return
    else
        perror "要先安装 fzf 哇"
        return 1
    fi
}



# Pack current result directory into update.tar.gz and open file manager
pwnm_cmd_pack_update(){
	local dir
	dir="$(pwd)"
	local base
	base="$(basename "$dir")"
	if [ "$base" != "result" ]; then
		perror "要在 awdp 题目文件的 result 文件夹下使用噢 (⊙o⊙)"
		return 1
	fi
	local out
	out="update.tar.gz"
	if command -v tar >/dev/null 2>&1; then
		# Exclude the output file itself if it exists
		if [ -f "$out" ]; then rm -f "$out"; fi
		if ls -A 1>/dev/null 2>&1; then
			tar -czf "$out" \
				--exclude "$out" \
				--exclude-vcs \
				-- *
		else
			# create empty tar.gz
			tar -czf "$out" --files-from /dev/null 2>/dev/null || pwarn "目录为空 (⊙o⊙)"
		fi
		psuccess "打包成功ovo: $dir/$out"
		pwnm_open_folder "$dir"
		return 0
	else
		perror "找不到 tar 命令 "
		return 1
	fi
}

# Clear libc or tag information for current problem
pwnm_cmd_unset(){
	[ "$#" -eq 0 ] && { perror "参数呢？！(tag 或 libc)"; return 1; }
	local param="$1"
	local dir meta contest problem
	dir="$(pwd)"
	meta="$dir/.pwnm/meta.json"
	[ -f "$meta" ] || { perror "找不到题目数据: $meta"; return 1; }
	
	case "$param" in
		tag)
			# Clear tags array
			if command -v jq >/dev/null 2>&1; then
				local content
				content="$(cat "$meta")"
				content="$(printf '%s' "$content" | jq '.tags = []')"
				printf '%s' "$content" > "$meta"
			else
				sed -i.bak 's/"tags"[[:space:]]*:\[[^]]*\]/"tags": []/' "$meta" 2>/dev/null || true
				rm -f "$meta.bak" 2>/dev/null || true
			fi
			# Update index
			contest="$(basename "$(dirname "$dir")")"
			problem="$(basename "$dir")"
			local libc archv relro canary nx pie created
			libc="$(sed -n 's/.*"libc": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
			archv="$(sed -n 's/.*"arch": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
			relro=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"RELRO": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
			canary=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"CANARY": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
			nx=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"NX": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
			pie=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"PIE": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
			created="$(sed -n 's/.*"created_at": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
			pwnm_index_add "$contest" "$problem" "$dir" "$libc" "$archv" "$relro" "$canary" "$nx" "$pie" "None" "$created"
			psuccess "标签已清空√"
			;;
		libc)
			# Clear libc information
			sed -i.bak 's/"libc": "[^"]*"/"libc": "None"/' "$meta" 2>/dev/null || true
			rm -f "$meta.bak" 2>/dev/null || true
			# Update index
			contest="$(basename "$(dirname "$dir")")"
			problem="$(basename "$dir")"
			local archv relro canary nx pie typ created
			archv="$(sed -n 's/.*"arch": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
			relro=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"RELRO": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
			canary=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"CANARY": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
			nx=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"NX": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
			pie=$(sed -n '/"protections"/,/}/ { s/^[[:space:]]*"PIE": "\([^"]*\)".*/\1/p }' "$meta" | head -n1)
			created="$(sed -n 's/.*"created_at": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
			if command -v jq >/dev/null 2>&1; then
				typ="$(jq -r '(.tags // []) | join(",")' "$meta" 2>/dev/null)"
			else
				typ="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1 | sed 's/\"//g')"
			fi
			[ -z "$typ" ] && typ="None"
			pwnm_index_add "$contest" "$problem" "$dir" "None" "$archv" "$relro" "$canary" "$nx" "$pie" "$typ" "$created"
			psuccess "libc 信息已清空√"
			;;
		*)
			perror "不支持的参数: $param (只支持 tag 或 libc)"
			return 1
			;;
	esac
}

# Show current problem info
pwnm_cmd_show_info(){
	local dir="$(pwd)"
	local meta="$dir/.pwnm/meta.json"
	[ -f "$meta" ] || { perror "找不到题目数据: $meta"; return 1; }

	# Extract all fields using jq
	local contest problem libc arch endian relro canary nx pie tagsv created

	if command -v jq >/dev/null 2>&1; then
		contest="$(jq -r '.contest // "Unknown"' "$meta" 2>/dev/null)"
		problem="$(jq -r '.problem // "Unknown"' "$meta" 2>/dev/null)"
		libc="$(jq -r '.libc // "None"' "$meta" 2>/dev/null)"
		arch="$(jq -r '.arch // "None"' "$meta" 2>/dev/null)"
		endian="$(jq -r '.endian // "None"' "$meta" 2>/dev/null)"
		relro="$(jq -r '.protections.RELRO // "None"' "$meta" 2>/dev/null)"
		canary="$(jq -r '.protections.CANARY // "None"' "$meta" 2>/dev/null)"
		nx="$(jq -r '.protections.NX // "None"' "$meta" 2>/dev/null)"
		pie="$(jq -r '.protections.PIE // "None"' "$meta" 2>/dev/null)"
		tagsv="$(jq -r '(.tags // []) | join(",")' "$meta" 2>/dev/null)"
		created="$(jq -r '.created_at // "Unknown"' "$meta" 2>/dev/null)"
	else
		# Fallback to sed if jq not available
		contest="$(sed -n 's/.*"contest": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
		problem="$(sed -n 's/.*"problem": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
		libc="$(sed -n 's/.*"libc": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
		arch="$(sed -n 's/.*"arch": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
		endian="$(sed -n 's/.*"endian": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
		# Use grep and sed for protections (handle both multiline and single-line JSON)
		relro="$(grep -o '"RELRO":"[^"]*"' "$meta" | sed 's/"RELRO":"\([^"]*\)"/\1/' | head -n1)"
		canary="$(grep -o '"CANARY":"[^"]*"' "$meta" | sed 's/"CANARY":"\([^"]*\)"/\1/' | head -n1)"
		nx="$(grep -o '"NX":"[^"]*"' "$meta" | sed 's/"NX":"\([^"]*\)"/\1/' | head -n1)"
		pie="$(grep -o '"PIE":"[^"]*"' "$meta" | sed 's/"PIE":"\([^"]*\)"/\1/' | head -n1)"
		tagsv="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1 | sed 's/\"//g')"
		created="$(sed -n 's/.*"created_at": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"

		# Set defaults for empty values
		[ -z "$contest" ] && contest="Unknown"
		[ -z "$problem" ] && problem="Unknown"
		[ -z "$libc" ] && libc="None"
		[ -z "$arch" ] && arch="None"
		[ -z "$endian" ] && endian="None"
		[ -z "$relro" ] && relro="None"
		[ -z "$canary" ] && canary="None"
		[ -z "$nx" ] && nx="None"
		[ -z "$pie" ] && pie="None"
		[ -z "$created" ] && created="Unknown"
	fi

	[ -z "$tagsv" ] && tagsv="None"

	# Pretty print
	echo "[======================✨ $contest : $problem ======================]"
	echo "📚 libc: $libc | 📚 arch: $arch | 📚 endian: $endian"
	echo ""
	echo "[======================🛡️ 保护机制 ======================]"
	echo "▷ RELRO: $relro"
	echo "▷ CANARY: $canary"
	echo "▷ NX: $nx"
	echo "▷ PIE: $pie"
	echo ""
	echo "[======================🏷️ 其他信息 ======================]"
	echo "▫️ tags: $tagsv"
	echo "▫️ created_at: $created"
}

# Open folder command
pwnm_cmd_open(){
	local target_dir="$1"

	# If no argument provided, use current directory
	if [ -z "$target_dir" ]; then
		target_dir="$(pwd)"
		pinfo "打开当前目录: $target_dir"
	else
		# Check if the specified directory exists
		if [ ! -d "$target_dir" ]; then
			perror "目录不存在: $target_dir"
			return 1
		fi
		pinfo "打开目录: $target_dir"
	fi

	# Open the folder using pwnm_open_folder
	pwnm_open_folder "$target_dir"

	if [ $? -eq 0 ]; then
		psuccess "已打开文件夹"
	else
		pwarn "无法打开文件夹，请检查系统是否支持文件管理器"
	fi
}

# Auto solve command - AI assistant integration
pwnm_cmd_auto(){
	local dir solve_dir session_file auto_solver_script
	dir="$(pwd)"
	solve_dir="$dir/solve"
	session_file="$solve_dir/session_id"

	# Get auto solver script path
	auto_solver_script="$PWNM_DIR/lib/auto_solver/pwn_auto_solver.sh"

	if [ ! -f "$auto_solver_script" ]; then
		perror "找不到 AI 自动解题脚本: $auto_solver_script"
		return 1
	fi

	# Check if session_id exists
	if [ -f "$session_file" ]; then
		local session_id
		session_id=$(cat "$session_file" 2>/dev/null | tr -d '[:space:]')

		if [ -n "$session_id" ]; then
			echo ""
			pinfo "检测到已存在的 AI 会话: $session_id"
			pinfo "是否需要与当前 session 进行对话？(y/n)"
			read -r interact
			interact=$(pwnm_tolower "$interact")

			if [ "$interact" = "y" ] || [ "$interact" = "yes" ]; then
				# Direct interaction with Claude
				pinfo "启动 AI 对话..."
				claude --resume "$session_id"
				return $?
			else
				# Continue auto solve with user prompt
				echo ""
				pinfo "请输入题目文件名 (直接回车默认为 pwn):"
				read -r pwn_file
				[ -z "$pwn_file" ] && pwn_file="pwn"

				echo ""
				pinfo "请输入新的分析指令:"
				read -r user_prompt

				# If empty, ask if user wants to exit
				while [ -z "$user_prompt" ]; do
					echo ""
					pinfo "未输入内容，是否结束？(y/n)"
					read -r exit_choice
					exit_choice=$(pwnm_tolower "$exit_choice")

					if [ "$exit_choice" = "y" ] || [ "$exit_choice" = "yes" ]; then
						pinfo "已取消操作"
						return 0
					else
						echo ""
						pinfo "请输入新的分析指令:"
						read -r user_prompt
					fi
				done

				# Resume auto solve with custom prompt
				"$auto_solver_script" -f "$pwn_file" --resume "$session_id" -p "$user_prompt"
				return $?
			fi
		fi
	fi

	# First time run - no session_id exists
	echo ""
	pinfo "请输入题目文件名 (直接回车默认为 pwn):"
	read -r pwn_file
	[ -z "$pwn_file" ] && pwn_file="pwn"

	echo ""
	pinfo "请输入题目描述 (直接回车跳过):"
	read -r description

	# Build arguments
	local args="-f $pwn_file"
	[ -n "$description" ] && args="$args -d \"$description\""

	# Run auto solver
	eval "$auto_solver_script $args"
	return $?
}

# Aliases to be used by pwnm.sh dispatcher
pwnm_perror(){ perror "$@"; }