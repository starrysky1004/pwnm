#!/usr/bin/env bash
# Author: starrysky
# Contributor： Rimuawa

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
	"$PWNM_DIR/../lib/common.sh" \
	"$(pwd)/lib/common.sh"; do
	if [ -f "$__cand" ]; then
		. "$__cand" && __pwnm_common_ok=1 && break
	fi
done
if [ "$__pwnm_common_ok" -ne 1 ]; then
	return 1 2>/dev/null || exit 1
fi

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
		c) pwnm_cmd_contest_create "$@" ;;
		g) pwnm_cmd_contest_goto "$@" ;;
		l|ls) pwnm_cmd_contest_list "$@" ;;
		n) pwnm_cmd_new_problem "$@" ;;
		cs) pwnm_cmd_checksec "$@" ;;
		gl) pwnm_cmd_glibc "$@" ;;
		t) pwnm_cmd_mark_type "$@" ;;
		st) pwnm_cmd_search_tui "$@" ;;
		info|i) pwnm_cmd_show_info "$@" ;;
		upd|pack) pwnm_cmd_pack_update "$@" ;;
		""|help|-h|--help)
			cat <<'HLP'
用法: pwnm <命令> [参数]
  init [ROOT] [GLIBC]       初始化工作区，指定存放题目的路径和 glibc-all-in-one 路径
  c <contest>               新建比赛并进入目录
  g <contest>               进入比赛
  l, ls                     列出所有比赛
  n <name> [--awd|--awdp]   在当前比赛中新建题目
  cs <binary file>          对二进制文件执行 checksec 并重命名为 pwn
  gl <libc file>            解析 GLIBC 版本，获取 libc、ld 并 patchelf 替换给 pwn 文件
  t <tag> [tag2 ...]        添加标签
  st                        可视化筛选
  i, info                   展示当前题目的信息
  upd, pack                 在 awdp 的 result 目录打包为 update.tar.gz
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

