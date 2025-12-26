#!/usr/bin/env bash
# Author: starrysky
# Contributor: Rimuawa
# Description: Markdown report generator from solve output JSON

# Check arguments
if [ $# -lt 2 ]; then
    echo "用法: $0 <input_json> <output_md> [--append]" >&2
    exit 1
fi

INPUT_JSON="$1"
OUTPUT_MD="$2"
APPEND_MODE=false

# Check for append flag
if [ "$3" = "--append" ]; then
    APPEND_MODE=true
fi

# Check input file
if [ ! -f "$INPUT_JSON" ]; then
    echo "错误: 输入文件不存在: $INPUT_JSON" >&2
    exit 1
fi

# Get tool result by tool_use_id
get_tool_result() {
    local tool_use_id="$1"
    # Use jq array processing with -s to avoid newline issues
    jq -rs --arg id "$tool_use_id" '
        map(select(.type == "user")) |
        map(.message.content[]?) |
        map(select(.type == "tool_result" and .tool_use_id == $id)) |
        if length > 0 then .[0].content // .[0].text // "" else "" end
    ' "$INPUT_JSON" 2>/dev/null
}

# Escape Markdown special characters
escape_md() {
    echo "$1" | sed 's/\\/\\\\/g'
}

# Output content (jq -r already converts \n, output directly without extra newlines)
output_content() {
    printf '%s' "$1"
}

# Start generating Markdown
if [ "$APPEND_MODE" = false ]; then
    # Create new file with header
    cat > "$OUTPUT_MD" <<'HEADER'
# PWN 题目分析报告

---

HEADER
else
    # Append mode: add separator
    cat >> "$OUTPUT_MD" <<'SEPARATOR'

---

## 继续分析

---

SEPARATOR
fi

# Process each message in JSON
jq -c 'select(.type == "assistant") | .message' "$INPUT_JSON" 2>/dev/null | while IFS= read -r message; do

    # Parse content array in message
    echo "$message" | jq -c '.content[]?' 2>/dev/null | while IFS= read -r content_item; do

        content_type=$(echo "$content_item" | jq -r '.type // empty' 2>/dev/null)

        case "$content_type" in
            text)
                # Output text content
                text=$(echo "$content_item" | jq -r '.text // ""' 2>/dev/null)
                echo "" >> "$OUTPUT_MD"
                output_content "$text" >> "$OUTPUT_MD"
                echo "" >> "$OUTPUT_MD"
                ;;

            tool_use)
                tool_name=$(echo "$content_item" | jq -r '.name // ""' 2>/dev/null)
                tool_use_id=$(echo "$content_item" | jq -r '.id // ""' 2>/dev/null)
                tool_input=$(echo "$content_item" | jq -c '.input // {}' 2>/dev/null)

                # Get corresponding result
                tool_result=$(get_tool_result "$tool_use_id")

                case "$tool_name" in
                    TodoWrite)
                        echo "" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "📋 Task List" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"

                        # Parse todos
                        echo "$tool_input" | jq -r '.todos[]? | "- [\(.status == "completed" | if . then "x" else " " end)] \(if .status == "in_progress" then "🟢" elif .status == "completed" then "✅" else "🔴" end) \(.content)"' >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        ;;

                    Bash)
                        description=$(echo "$tool_input" | jq -r '.description // "Execute command"' 2>/dev/null)
                        command=$(echo "$tool_input" | jq -r '.command // ""' 2>/dev/null)

                        echo "" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "⚡ $description" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo '```bash' >> "$OUTPUT_MD"
                        output_content "$command" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo '```' >> "$OUTPUT_MD"

                        # Output result
                        if [ -n "$tool_result" ]; then
                            echo "" >> "$OUTPUT_MD"
                            echo "**Execution Result:**" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                            echo '```' >> "$OUTPUT_MD"
                            output_content "$tool_result" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                            echo '```' >> "$OUTPUT_MD"
                        fi
                        echo "" >> "$OUTPUT_MD"
                        ;;

                    Read)
                        file_path=$(echo "$tool_input" | jq -r '.file_path // ""' 2>/dev/null)

                        # Detect file type
                        file_ext="${file_path##*.}"
                        lang="text"
                        case "$file_ext" in
                            py) lang="python" ;;
                            sh) lang="bash" ;;
                            c|cpp|cc|h) lang="c" ;;
                            js) lang="javascript" ;;
                            json) lang="json" ;;
                            md) lang="markdown" ;;
                            txt) lang="text" ;;
                        esac

                        echo "" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "📖 Read File" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "File: \`$file_path\`" >> "$OUTPUT_MD"

                        # Output read result
                        if [ -n "$tool_result" ]; then
                            echo "" >> "$OUTPUT_MD"
                            echo "**Content:**" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                            echo "\`\`\`$lang" >> "$OUTPUT_MD"
                            output_content "$tool_result" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                            echo '```' >> "$OUTPUT_MD"
                        fi
                        echo "" >> "$OUTPUT_MD"
                        ;;

                    Write)
                        file_path=$(echo "$tool_input" | jq -r '.file_path // ""' 2>/dev/null)
                        content=$(echo "$tool_input" | jq -r '.content // ""' 2>/dev/null)

                        # Detect file type
                        file_ext="${file_path##*.}"
                        lang="text"
                        case "$file_ext" in
                            py) lang="python" ;;
                            sh) lang="bash" ;;
                            c|cpp|cc) lang="c" ;;
                            js) lang="javascript" ;;
                            json) lang="json" ;;
                            md) lang="markdown" ;;
                        esac

                        echo "" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "✍️ Write File" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "File: \`$file_path\`" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "\`\`\`$lang" >> "$OUTPUT_MD"
                        output_content "$content" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo '```' >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        ;;

                    Edit)
                        file_path=$(echo "$tool_input" | jq -r '.file_path // ""' 2>/dev/null)
                        old_string=$(echo "$tool_input" | jq -r '.old_string // ""' 2>/dev/null)
                        new_string=$(echo "$tool_input" | jq -r '.new_string // ""' 2>/dev/null)

                        # Detect file type
                        file_ext="${file_path##*.}"
                        lang="text"
                        case "$file_ext" in
                            py) lang="python" ;;
                            sh) lang="bash" ;;
                            c|cpp|cc) lang="c" ;;
                            js) lang="javascript" ;;
                            json) lang="json" ;;
                            md) lang="markdown" ;;
                        esac

                        echo "" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "📝 Edit File" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "File: \`$file_path\`" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"

                        echo "**Old Content:**" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "\`\`\`$lang" >> "$OUTPUT_MD"
                        output_content "$old_string" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo '```' >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"

                        echo "**New Content:**" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "\`\`\`$lang" >> "$OUTPUT_MD"
                        output_content "$new_string" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo '```' >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        ;;

                    Glob)
                        pattern=$(echo "$tool_input" | jq -r '.pattern // ""' 2>/dev/null)

                        echo "" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "🔍 Find Files" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "Pattern: \`$pattern\`" >> "$OUTPUT_MD"

                        if [ -n "$tool_result" ]; then
                            echo "" >> "$OUTPUT_MD"
                            echo "**Result:**" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                            echo '```' >> "$OUTPUT_MD"
                            output_content "$tool_result" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                            echo '```' >> "$OUTPUT_MD"
                        fi
                        echo "" >> "$OUTPUT_MD"
                        ;;

                    Grep)
                        pattern=$(echo "$tool_input" | jq -r '.pattern // ""' 2>/dev/null)
                        path=$(echo "$tool_input" | jq -r '.path // "."' 2>/dev/null)

                        echo "" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "🔍 Search Content" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "Pattern: \`$pattern\`" >> "$OUTPUT_MD"
                        echo "Path: \`$path\`" >> "$OUTPUT_MD"

                        if [ -n "$tool_result" ]; then
                            echo "" >> "$OUTPUT_MD"
                            echo "**Result:**" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                            echo '```' >> "$OUTPUT_MD"
                            output_content "$tool_result" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                            echo '```' >> "$OUTPUT_MD"
                        fi
                        echo "" >> "$OUTPUT_MD"
                        ;;

                    mcp__*)
                        # MCP tool call
                        echo "" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo " 🔧 \`$tool_name\`" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"

                        # Output parameters (if any)
                        params=$(echo "$tool_input" | jq -r 'to_entries | map("\(.key): \(.value)") | join(", ")' 2>/dev/null)
                        if [ -n "$params" ] && [ "$params" != "" ]; then
                            echo "**Parameters:** $params" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                        fi

                        # Output result
                        if [ -n "$tool_result" ]; then
                            echo "**Result:**" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"

                            # Try to format JSON result
                            if echo "$tool_result" | jq empty 2>/dev/null; then
                                echo '```json' >> "$OUTPUT_MD"
                                echo "$tool_result" | jq '.' >> "$OUTPUT_MD"
                                echo '```' >> "$OUTPUT_MD"
                            else
                                echo '```' >> "$OUTPUT_MD"
                                output_content "$tool_result" >> "$OUTPUT_MD"
                                echo "" >> "$OUTPUT_MD"
                                echo '```' >> "$OUTPUT_MD"
                            fi
                        fi
                        echo "" >> "$OUTPUT_MD"
                        ;;

                    *)
                        # Other tools
                        echo "" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"
                        echo "🔧 $tool_name" >> "$OUTPUT_MD"
                        echo "" >> "$OUTPUT_MD"

                        if [ -n "$tool_result" ]; then
                            echo "**Result:**" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                            echo '```' >> "$OUTPUT_MD"
                            output_content "$tool_result" >> "$OUTPUT_MD"
                            echo "" >> "$OUTPUT_MD"
                            echo '```' >> "$OUTPUT_MD"
                        fi
                        echo "" >> "$OUTPUT_MD"
                        ;;
                esac
                ;;
        esac
    done
done