#!/usr/bin/env bash
# Author: starrysky
# Contributor: Rimuawa
# Description: Claude Code output formatter and prettifier

# Color definitions
COLOR_RESET='\033[0m'
COLOR_RED='\033[01;38;5;1m'
COLOR_ORANGE='\033[01;38;5;214m'
COLOR_GREEN='\033[01;38;5;2m'
COLOR_BLUE='\033[01;38;5;4m'
COLOR_YELLOW='\033[01;38;5;3m'
COLOR_CYAN='\033[01;38;5;6m'
COLOR_PURPLE='\033[01;38;5;5m'
COLOR_GRAY='\033[01;38;5;240m'

# Emoji definitions
EMOJI_IN_PROGRESS="🟢"
EMOJI_PENDING="🔴"
EMOJI_COMPLETED="✅"
EMOJI_BASH="⚡"
EMOJI_READ="📖"
EMOJI_WRITE="✍️"
EMOJI_EDIT="📝"
EMOJI_TODO="📋"
EMOJI_TOOL="🔧"
EMOJI_TEXT="💬"

# Draw box lines
draw_box_top() {
    echo -e "${COLOR_CYAN}╔════════════════════════════════════════════════════════════════${COLOR_RESET}"
}

draw_box_middle() {
    echo -e "${COLOR_CYAN}╠════════════════════════════════════════════════════════════════${COLOR_RESET}"
}

draw_box_bottom() {
    echo -e "${COLOR_CYAN}╚════════════════════════════════════════════════════════════════${COLOR_RESET}"
}

draw_box_line() {
    local text="$1"
    echo -e "${COLOR_CYAN}║${COLOR_RESET} ${text}"
}

# Process \n escape sequences to real newlines
unescape_newlines() {
    # Use printf to interpret escape sequences
    echo -e "$1"
}

# Format TodoWrite
format_todo() {
    local todos="$1"

    echo ""
    echo -e "${COLOR_PURPLE}${EMOJI_TODO} TodoWrite${COLOR_RESET}"
    draw_box_top

    # Parse todos array
    echo "$todos" | jq -r '.[] | "\(.status)|\(.content)|\(.activeForm)"' 2>/dev/null | while IFS='|' read -r status content activeForm; do
        case "$status" in
            in_progress)
                draw_box_line "${EMOJI_IN_PROGRESS} ${content}"
                ;;
            pending)
                draw_box_line "${EMOJI_PENDING} ${content}"
                ;;
            completed)
                draw_box_line "${EMOJI_COMPLETED} ${content}"
                ;;
            *)
                draw_box_line "  ${content}"
                ;;
        esac
    done

    draw_box_bottom
    echo ""
}

# Format Bash
format_bash() {
    local description="$1"
    local command="$2"

    echo ""
    echo -e "${COLOR_YELLOW}${EMOJI_BASH} ${description}${COLOR_RESET}"
    echo -e "${COLOR_GRAY}$ ${command}${COLOR_RESET}"
    echo ""
}

# Format Read
format_read() {
    local file_path="$1"

    echo ""
    echo -e "${COLOR_BLUE}${EMOJI_READ} Read: ${file_path}${COLOR_RESET}"
    echo ""
}

# Format Write
format_write() {
    local file_path="$1"
    local content="$2"

    echo ""
    echo -e "${COLOR_GREEN}${EMOJI_WRITE} Write: ${file_path}${COLOR_RESET}"
    echo -e "${COLOR_GRAY}───────────────────────────────────────────${COLOR_RESET}"
    unescape_newlines "$content"
    echo -e "${COLOR_GRAY}───────────────────────────────────────────${COLOR_RESET}"
    echo ""
}

# Format Edit
format_edit() {
    local file_path="$1"
    local old_string="$2"
    local new_string="$3"

    echo ""
    echo -e "${COLOR_ORANGE}${EMOJI_EDIT} Edit: ${file_path}${COLOR_RESET}"
    echo -e "${COLOR_RED}old_string:${COLOR_RESET}"
    unescape_newlines "$old_string"
    echo ""
    echo -e "${COLOR_GREEN}new_string:${COLOR_RESET}"
    unescape_newlines "$new_string"
    echo -e "${COLOR_GRAY}───────────────────────────────────────────${COLOR_RESET}"
    echo ""
}

# Format MCP tool call
format_mcp_tool() {
    local tool_name="$1"

    echo ""
    echo -e "${COLOR_CYAN}${EMOJI_TOOL} ${tool_name}${COLOR_RESET}"
    echo ""
}

# Format text content
format_text() {
    local text="$1"

    echo ""
    echo -e "${EMOJI_TEXT} ${COLOR_RESET}"
    unescape_newlines "$text"
    echo ""
}

# Main processing loop
while IFS= read -r line; do
    # Skip empty lines
    [ -z "$line" ] && continue

    # Try to parse JSON
    type=$(echo "$line" | jq -r '.type // empty' 2>/dev/null)

    case "$type" in
        assistant)
            # Parse assistant message
            content_array=$(echo "$line" | jq -c '.message.content[]?' 2>/dev/null)

            echo "$content_array" | while IFS= read -r content_item; do
                content_type=$(echo "$content_item" | jq -r '.type // empty' 2>/dev/null)

                case "$content_type" in
                    text)
                        text=$(echo "$content_item" | jq -r '.text // empty' 2>/dev/null)
                        format_text "$text"
                        ;;

                    tool_use)
                        tool_name=$(echo "$content_item" | jq -r '.name // empty' 2>/dev/null)
                        tool_input=$(echo "$content_item" | jq -c '.input // {}' 2>/dev/null)

                        case "$tool_name" in
                            TodoWrite)
                                todos=$(echo "$tool_input" | jq -c '.todos // []' 2>/dev/null)
                                format_todo "$todos"
                                ;;

                            Bash)
                                description=$(echo "$tool_input" | jq -r '.description // "执行命令"' 2>/dev/null)
                                command=$(echo "$tool_input" | jq -r '.command // ""' 2>/dev/null)
                                format_bash "$description" "$command"
                                ;;

                            Read)
                                file_path=$(echo "$tool_input" | jq -r '.file_path // ""' 2>/dev/null)
                                format_read "$file_path"
                                ;;

                            Write)
                                file_path=$(echo "$tool_input" | jq -r '.file_path // ""' 2>/dev/null)
                                content=$(echo "$tool_input" | jq -r '.content // ""' 2>/dev/null)
                                format_write "$file_path" "$content"
                                ;;

                            Edit)
                                file_path=$(echo "$tool_input" | jq -r '.file_path // ""' 2>/dev/null)
                                old_string=$(echo "$tool_input" | jq -r '.old_string // ""' 2>/dev/null)
                                new_string=$(echo "$tool_input" | jq -r '.new_string // ""' 2>/dev/null)
                                format_edit "$file_path" "$old_string" "$new_string"
                                ;;

                            mcp__*)
                                format_mcp_tool "$tool_name"
                                ;;

                            *)
                                # 其他工具
                                format_mcp_tool "$tool_name"
                                ;;
                        esac
                        ;;
                esac
            done
            ;;

        *)
            # Other message types, choose to ignore or output as-is
            # echo "$line"
            ;;
    esac
done
