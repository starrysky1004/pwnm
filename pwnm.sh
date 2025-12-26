#!/usr/bin/env bash
# Author: starrysky
# Contributor： Rimuawa
# Description: PWN problem management tool

# Resolve script directory across bash/zsh/source
if [ -n "$BASH_VERSION" ]; then
	PWNM_SRC="${BASH_SOURCE[0]}"
elif [ -n "$ZSH_VERSION" ]; then
	PWNM_SRC="${(%):-%N}"
else
	PWNM_SRC="$0"
fi
PWNM_DIR="$(cd "$(dirname "$PWNM_SRC")" 2>/dev/null && pwd || pwd)"  # <repo>/tools

# Try to source common.sh from repo lib (silent if missing)
__pwnm_common_ok=0
for __cand in \
	"$PWNM_DIR/lib/common.sh" \
	"$(pwd)/lib/common.sh"; do
	if [ -f "$__cand" ]; then
		. "$__cand" && __pwnm_common_ok=1 && break
	fi
done
if [ "$__pwnm_common_ok" -ne 1 ]; then
	return 1 2>/dev/null || exit 1
fi

pwnm_banner_pink() {
	echo -e "\033[38;2;255;105;180m╔═══════════════════════════════════╗\033[0m"
	echo -e "\033[38;2;255;130;200m║  ▄▄▄▄   ▄     ▄  ▄   ▄  ▄     ▄   ║\033[0m"
	echo -e "\033[38;2;255;150;210m║  █▀▀█▄  █     █  █▀▄ █  █▀▄ ▄▀█   ║\033[0m"
	echo -e "\033[38;2;255;170;220m║  █▄▄█▀  █  █  █  █  ▀█  █  ▀  █   ║\033[0m"
	echo -e "\033[38;2;255;190;230m║  █      ▀▄▄█▄▄▀  █   █  █     █   ║\033[0m"
	echo -e "\033[38;2;230;200;255m║                                   ║\033[0m"
	echo -e "\033[38;2;230;200;255m║      pwn challenge manager ❤      ║\033[0m"
	echo -e "\033[38;2;255;105;180m╚═══════════════════════════════════╝\033[0m"
}

pwnm_rescan_index() {
	# Rebuild ~/.pwnm/index.tsv by pruning deleted workdirs and normalizing schema
	pwnm_load_config
	[ -f "$PWNM_INDEX" ] || return 0

	local tmpdir infl
	tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/.pwnm_rescan_$$")
	mkdir -p "$tmpdir" 2>/dev/null || true
	infl="$PWNM_INDEX"

	local i=0
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		i=$((i+1))

		local contest problem workdir libc arch relro canary nx pie typ created
		IFS=$'\t' read -r contest problem workdir libc arch relro canary nx pie typ created <<< "$line"
		if [ -d "$workdir" ]; then
			printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
				"$contest" "$problem" "$workdir" "$libc" "$arch" "$relro" "$canary" "$nx" "$pie" "$typ" "$created" \
				> "$tmpdir/$i.tsv"
		fi
	done < "$infl"

	local out tmp
	out="$PWNM_INDEX.tmp"
	: > "$out"
	for tmp in "$tmpdir"/*.tsv; do
		[ -f "$tmp" ] || continue
		cat "$tmp" >> "$out"
	done
	mv -f "$out" "$PWNM_INDEX" 2>/dev/null || cp -f "$out" "$PWNM_INDEX"
	rm -rf "$tmpdir" 2>/dev/null || true
}

pwnm() {
	local cmd="$1"; shift 2>/dev/null || true

	case "$cmd" in
		init) pwnm_cmd_init "$@" ;;
		new) pwnm_cmd_contest_create "$@" ;;
		cd) pwnm_cmd_contest_goto "$@" ;;
		ls) pwnm_cmd_contest_list "$@" ;;
		add) pwnm_cmd_new_problem "$@" ;;
		cs) pwnm_cmd_checksec "$@" ;;
		gl) pwnm_cmd_glibc "$@" ;;
		t) pwnm_cmd_mark_type "$@" ;;
		st) pwnm_cmd_search_tui "$@" ;;
		info|i) pwnm_cmd_show_info "$@" ;;
		pack) pwnm_cmd_pack_update "$@" ;;
		unset) pwnm_cmd_unset "$@" ;;
		auto) pwnm_cmd_auto "$@" ;;
		open) pwnm_cmd_open "$@" ;;
		""|help|-h|--help)
			pwnm_banner_pink
			cat <<'HLP'

用法: pwnm <命令> [参数]

⚡ 初始化:
  init [ROOT] [GLIBC]       ⚙️ 初始化工作区（可选自动安装 pwn 环境

📋 比赛管理:
  new <contest>             🆕 新建比赛
  cd <contest>              📂 进入比赛
  ls	                    📜 列出所有比赛

🎯 题目管理:
  add <name> [--awd|--awdp] ➕ 添加题目
  st                        🎨 可视化筛选，回车进入目录

🔧 工具命令:
    🚀 解题工具：
	cs <binary file>          🔍 checksec 并重命名为 pwn
	gl <libc file>            📦 识别 libc 版本并替换 libc 和 ld（file 不填默认为 pwn
	auto                      🤖 AI 自动解题

   🎬 辅助工具：
	t <tag>                   🏷️  添加标签，可以一次性添加多个 tag(不会被空格截断，形式：t tag1 t tag2)
	i, info                   ℹ️  在题目文件夹下展示当前题目信息
	unset <tag|libc>          ❌ 清空 tag 或 libc 信息
	pack                      📦 在 awdp 类型题目的 result 文件夹下打包 update.tar.gz
	open [path]               📂 打开文件夹（默认当前目录）

HLP
			;;
		*) pwnm_perror "Unknown command: $cmd"; return 1 ;;
	esac
}

# If executed directly: run as a one-off. If sourced: silent background rescan.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    pwnm "$@"
else
	pwnm_rescan_index >/dev/null 2>&1
fi
