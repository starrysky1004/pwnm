#!/usr/bin/env bash

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

pwnm_detect_repo_root(){
	# Walk up to find a recognizable repo root
	local d
	d="$(pwd)"
	while [ "$d" != "/" ]; do
		if [ -f "$d/exp.py" ] || [ -d "$d/AwdPwnPatcher" ] || [ -d "$d/awdpwn" ]; then
			REPO_ROOT="$d"
			return 0
		fi
		d="$(dirname "$d")"
	done
	return 1
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
	if command -v code >/dev/null 2>&1; then
		code "$dir" >/dev/null 2>&1 &
	elif command -v xdg-open >/dev/null 2>&1; then
		xdg-open "$dir" >/dev/null 2>&1 &
	elif command -v open >/dev/null 2>&1; then
		open "$dir" >/dev/null 2>&1 &
	elif command -v explorer.exe >/dev/null 2>&1; then
		# WSL: open with Windows Explorer
		if command -v wslpath >/dev/null 2>&1; then
			explorer.exe "$(wslpath -w "$dir")" >/dev/null 2>&1 &
		else
			explorer.exe "$dir" >/dev/null 2>&1 &
		fi
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
		"type": "None",
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
		[ -z "$typ" ] && typ="$(sed -n 's/.*"type": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	else
		local tags_line
		tags_line="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1 | sed 's/\"//g')"
		if [ -n "$tags_line" ]; then typ="$tags_line"; else typ="$(sed -n 's/.*"type": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"; fi
	fi
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
	
	if command -v jq >/dev/null 2>&1; then
		typ="$(jq -r '(.tags // []) | join(",")' "$meta" 2>/dev/null)"
		[ -z "$typ" ] && typ="$(grep -o '"type": "[^"]*"' "$meta" | cut -d'"' -f4)"
	else
		local rawtags
		rawtags="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1 | sed 's/\"//g')"
		if [ -n "$rawtags" ]; then typ="$rawtags"; else typ="$(grep -o '"type": "[^"]*"' "$meta" | cut -d'"' -f4)"; fi
	fi
	
	if ! grep -q '"tags"' "$meta" 2>/dev/null; then
		awk '{
			print $0
			if ($0 ~ /"type"[[:space:]]*:/) { print "\t\t\"tags\": []," }
		}' "$meta" > "$meta.tmp" && mv -f "$meta.tmp" "$meta"
	fi

	if command -v jq >/dev/null 2>&1; then
		local content tag
		content="$(cat "$meta")"
		for tag in "$@"; do
			content="$(printf '%s' "$content" | jq --arg t "$tag" '.tags = ((.tags // []) + [$t]) | .tags |= unique')"
		done
		content="$(printf '%s' "$content" | jq '.type = ((.tags // []) | join(","))')"
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
		local typestr
		typestr="$(printf '%s' "$newlist" | sed 's/\"//g')"

		sed -i.bak "s/\"type\": \"[^\"]*\"/\"type\": \"$typestr\"/" "$meta" 2>/dev/null || true
		rm -f "$meta.bak" 2>/dev/null || true
	fi

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
		[ -z "$typ" ] && typ="$(sed -n 's/.*"type": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	else
		local tags_line
		tags_line="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1 | sed 's/\"//g')"
		if [ -n "$tags_line" ]; then typ="$tags_line"; else typ="$(sed -n 's/.*"type": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"; fi
	fi

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
	printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
			"比赛名称" "题目名称" "路径" "Libc" "Arch" \
			"RELRO" "Canary" "NX" "PIE" "题目类型" "创建时间"
	while IFS=$'\t' read -r contest problem workdir libc arch relro can nx pie typ created; do
		[ -z "$contest" ] && continue
		local endianv="" created_ym=""
		created_ym=$(printf "%s" "$created" | cut -c1-7)
		[ -z "$created_ym" ] && created_ym=$(printf "%s" "$created" | awk -F'-' '{print $1"-"$2}')
		printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
			"$contest" "$problem" "$workdir" "$libc" "$arch" \
			"$relro" "$can" "$nx" "$pie" "$typ" "$created_ym"
	done < "$PWNM_INDEX"
}
    
# Commands implementation wrappers
pwnm_cmd_init(){
	local root_dir="$1"; local glibc_dir="$2"
	pwnm_load_config
	[ -n "$root_dir" ] && PWNM_ROOT="$root_dir"
	[ -z "$PWNM_ROOT" ] && PWNM_ROOT="$HOME/pwndb_work"
	[ -n "$glibc_dir" ] && GLIBC_ALL_IN_ONE="$glibc_dir"
	$MKDIR_BIN -p "$PWNM_ROOT" "$PWNM_HOME" "$PWNM_HOME/templates"
	# bring templates from current repo
	if pwnm_detect_repo_root; then
		[ -f "$REPO_ROOT/exp.py" ] && cp -f "$REPO_ROOT/exp.py" "$PWNM_HOME/templates/exp.py" 2>/dev/null || true
		[ -d "$REPO_ROOT/AwdPwnPatcher" ] && cp -rf "$REPO_ROOT/AwdPwnPatcher" "$PWNM_HOME/templates/" 2>/dev/null || true
		[ -d "$REPO_ROOT/awdpwn" ] && cp -rf "$REPO_ROOT/awdpwn" "$PWNM_HOME/templates/" 2>/dev/null || true
		[ -d "$REPO_ROOT/result" ] && cp -rf "$REPO_ROOT/result" "$PWNM_HOME/templates/" 2>/dev/null || true
	fi
	pwnm_write_config "$PWNM_ROOT" "$GLIBC_ALL_IN_ONE"
	pinfo "安装工具ing..."
	sudo apt update -y && sudo apt install -y jq fzf binutils
	# shell integration: add function shortcut (does not modify PATH)
	local src_line="source $PWNM_DIR/pwnm.sh"
	for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
		if [ -f "$rc" ]; then
			grep -F "$src_line" "$rc" >/dev/null 2>&1 || echo "$src_line" >> "$rc"
		else
			echo "$src_line" >> "$rc"
		fi
	done
	psuccess "初始化完成，输入 pwnm 查看用法喵~"; echo "ROOT: $PWNM_ROOT"; [ -n "$GLIBC_ALL_IN_ONE" ] && echo "GLIBC: $GLIBC_ALL_IN_ONE"
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
		# Prepare result directory with only update.sh
		$MKDIR_BIN -p "$dir/result"
		if [ -f "$PWNM_HOME/templates/result/update.sh" ]; then
			cp -f "$PWNM_HOME/templates/result/update.sh" "$dir/result/update.sh" 2>/dev/null || true
		elif [ -d "$PWNM_HOME/templates/result" ]; then
			# fallback: copy any update.sh-like script if present
			for cand in "$PWNM_HOME/templates/result"/*.sh; do
				[ -f "$cand" ] || continue
				case "$(basename "$cand")" in update.sh) cp -f "$cand" "$dir/result/update.sh" ;; esac
			done
		fi
		# Remove unwanted files in result (mkupdate.sh, nested result, others)
		if [ -d "$dir/result/result" ]; then
			# flatten then remove inner dir
			cp -rf "$dir/result/result/." "$dir/result/" 2>/dev/null || true
			rm -rf "$dir/result/result" 2>/dev/null || true
		fi
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
	checksec $file

	# Update meta.json for info output
    local dir meta
	dir="$(cd "$(dirname "$file")" && pwd)"
	meta="$dir/.pwnm/meta.json"
	[ -f "$meta" ] || pwnm_init_problem_meta "$dir"
	# Update index.tsv to reflect latest protections/libc/tags
	local contest problem libc typ created
	contest="$(basename "$(dirname "$dir")")"
	problem="$(basename "$dir")"
	created="$(sed -n 's/.*"created_at": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	libc="$(sed -n 's/.*"libc": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"

	output=$(checksec --file="$file" 2>&1 | tr -cd '\11\12\15\40-\176')
	arch=$(echo "$output"   | grep "Arch:"  | awk '{split($2,a,"-"); print a[1]}')
	endian=$(echo "$output" | grep "Arch:"  | awk '{split($2,a,"-"); print a[3]}')
	relro=$(echo "$output"  | grep "RELRO:" | cut -d':' -f2- | xargs)
	stack=$(echo "$output"  | grep "Stack:" | cut -d':' -f2- | xargs)
	nx=$(echo "$output"     | grep "NX:"    | cut -d':' -f2- | xargs)
	pie=$(echo "$output"    | grep "PIE:"   | cut -d':' -f2- | xargs)

	if command -v jq >/dev/null 2>&1; then
		typ="$(jq -r '(.tags // []) | join(",")' "$meta" 2>/dev/null)"
		[ -z "$typ" ] && typ="$(sed -n 's/.*"type": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	else
		local tags_line
		tags_line="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1 | sed 's/\"//g')"
		if [ -n "$tags_line" ]; then typ="$tags_line"; else typ="$(sed -n 's/.*"type": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"; fi
	fi

	pwnm_index_add "$contest" "$problem" "$dir" "$libc" "$arch" "$relro" "$stack" "$nx" "$pie" "$typ" "$created"

	sed -i.bak -E "s/\"RELRO\":\"[^\"]*\"/\"RELRO\":\"${relro}\"/" "$meta" 2>/dev/null || true
	sed -i.bak -E "s/\"CANARY\":\"[^\"]*\"/\"CANARY\":\"${stack}\"/" "$meta" 2>/dev/null || true
	sed -i.bak -E "s/\"NX\":\"[^\"]*\"/\"NX\":\"${nx}\"/" "$meta" 2>/dev/null || true
	sed -i.bak -E "s/\"PIE\":\"[^\"]*\"/\"PIE\":\"${pie}\"/" "$meta" 2>/dev/null || true
	sed -i.bak -E "s/\"arch\": \"[^\"]*\"/\"arch\": \"${arch}\"/" "$meta" 2>/dev/null || true
	sed -i.bak -E "s/\"endian\": \"[^\"]*\"/\"endian\": \"${endian}\"/" "$meta" 2>/dev/null || true
	psuccess "已更新元信息 (info 可查看)"
	
	# Rename to pwn if needed
	local base
	base="$(basename "$file")"
	if [ "$base" != "pwn" ] && [ -f "$dir/$base" ]; then
		mv -f "$dir/$base" "$dir/pwn" && psuccess "已重命名为: $dir/pwn"
	fi
}

pwnm_cmd_glibc(){
	local file="$1"; [ -z "$file" ] && perror "文件名呢？！" && return 1
	[ ! -f "$file" ] && perror "是不是打错文件名了吖⭐" && return 1
	[ -z "$GLIBC_ALL_IN_ONE" ] || [ ! -d "$GLIBC_ALL_IN_ONE" ] && { perror "要先设置 glibc-all-in-one 路径w"; return 1; }
	# Prefer parsing full libc version from the GNU banner line:
	# Example line:
	# GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.17) stable release version 2.31.
	# Extract the text between "GLIBC " and the next ")" → 2.31-0ubuntu9.17
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
	libc_path=$(find "$cand" -maxdepth 3 -type f -name "libc.so.6" | head -n1)
	[ -z "$libc_path" ] && libc_path=$(find "$cand" -maxdepth 1 -type f -name "libc-*.so" | head -n1)
	# ld variants
	ld_path=$(find "$cand" -maxdepth 1 -type f \( -name "ld-*.so" -o -name "ld-linux*.so*" \) | head -n1)

	local libc_base ld_base
	if [ -n "$libc_path" ]; then
		libc_base="$(basename "$libc_path")"
		cp -f "$libc_path" "$dst/$libc_base"
	else
		pwarn "找不到 libc "
	fi
	if [ -n "$ld_path" ]; then
		ld_base="$(basename "$ld_path")"
		cp -f "$ld_path" "$dst/$ld_base"
	else
		pwarn "找不到 ld "
	fi

	pwnm_update_meta_libc "$dst" "$ver"

	# Optional: patch binary to use local ld and libc
	local bin="$dst/pwn"; [ -f "$bin" ] || bin="$file"
	if [ -f "$bin" ] && command -v patchelf >/dev/null 2>&1; then
		# get original libc name from ldd
		local orig_libc
		orig_libc=$(ldd "$bin" 2>/dev/null | awk '/libc\\.so/{print $1; exit}')
		[ -z "$orig_libc" ] && orig_libc="libc.so.6"
		if [ -n "$ld_base" ] && [ -f "$dst/$ld_base" ]; then
			patchelf --set-interpreter "./$ld_base" "$bin" 2>/dev/null || true
		fi
		if [ -n "$libc_base" ] && [ -f "$dst/$libc_base" ]; then
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

pwnm_cmd_mark_type(){ local t="$1"; [ -z "$t" ] && perror "题型呢？！" && return 1; pwnm_mark_type "$t"; }

pwnm_cmd_search_tui(){
    if command -v fzf >/dev/null 2>&1; then
        local contest problem workdir libc arch relro can nx pie typ created
        local tmpfile=$(mktemp)
        pwnm_index_to_lines > "$tmpfile"

        sel=$(column -t -s $'\t' "$tmpfile" | fzf --ansi --multi --header-lines=1 --layout=reverse)
        [ -z "$sel" ] && { rm -f "$tmpfile"; return 1; }

        local key=$(echo "$sel" | awk '{print $1 "\t" $2}')
        local original_line=$(grep -F "$key" "$tmpfile")

        IFS=$'\t' read -r contest problem workdir libc arch relro can nx pie typ created <<< "$original_line"

        rm -f "$tmpfile"

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
		perror "要 awdp 题目文件的 result 文件夹下使用噢 (⊙o⊙)"
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

# Show current problem info
pwnm_cmd_show_info(){
	local dir="$(pwd)"
	local meta="$dir/.pwnm/meta.json"
	[ -f "$meta" ] || { perror "找不到题目数据: $meta"; return 1; }
	if command -v jq >/dev/null 2>&1; then
		if jq . "$meta" >/dev/null 2>&1; then
			jq . "$meta"
			return 0
		else
			pwarn "meta.json 含有未转义字符，使用兼容模式输出"
		fi
	fi
	# Minimal sed extraction to avoid complex quoting in zsh
	local contest="$(sed -n 's/.*"contest": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	local problem="$(sed -n 's/.*"problem": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
    local workdirv="$(sed -n 's/.*"workdir": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	local libc="$(sed -n 's/.*"libc": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	local relro="$(sed -n 's/.*"RELRO":"\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	local canary="$(sed -n 's/.*"CANARY":"\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	local nx="$(sed -n 's/.*"NX":"\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	local pie="$(sed -n 's/.*"PIE":"\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	local typev="$(sed -n 's/.*"type": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	local tagsv
	if command -v jq >/dev/null 2>&1; then
		tagsv="$(jq -r '(.tags // []) | join(",")' "$meta" 2>/dev/null)"
	else
		tagsv="$(sed -n 's/.*"tags"[[:space:]]*:\[\(.*\)\].*/\1/p' "$meta" | head -n1 | sed 's/\"//g')"
	fi
	local created="$(sed -n 's/.*"created_at": "\([^"]*\)".*/\1/p' "$meta" | head -n1)"
	printf "contest: %s\n" "$contest"
	printf "problem: %s\n" "$problem"
    printf "path: %s\n" "$workdirv"
	printf "libc: %s\n" "$libc"
	printf "RELRO: %s\n" "$relro"
	printf "CANARY: %s\n" "$canary"
	printf "NX: %s\n" "$nx"
	printf "PIE: %s\n" "$pie"
	printf "type: %s\n" "$typev"
	[ -n "$tagsv" ] && printf "tags: %s\n" "$tagsv"
	printf "created_at: %s\n" "$created"
}

# Aliases to be used by pwnm.sh dispatcher
pwnm_perror(){ perror "$@"; }
