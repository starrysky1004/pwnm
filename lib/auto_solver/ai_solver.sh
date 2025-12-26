#!/usr/bin/env bash
# Author: starrysky
# Contributor: Rimuawa
# Description: Core AI solver functions and utilities

# Color definitions
COLOR_RESET='\033[0m'
COLOR_RED='\033[01;38;5;1m'
COLOR_ORANGE='\033[01;38;5;214m'
COLOR_GREEN='\033[01;38;5;2m'
COLOR_BLUE='\033[01;38;5;4m'
COLOR_YELLOW='\033[01;38;5;3m'
COLOR_CYAN='\033[01;38;5;6m'

# Logging functions
log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1" >&2
}

log_success() {
    echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} $1" >&2
}

log_warning() {
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} $1" >&2
}

log_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1" >&2
}

log_step() {
    echo -e "${COLOR_ORANGE}[STEP]${COLOR_RESET} $1" >&2
}

# MCP configuration file path
MCP_CONFIG_TEMPLATE="${HOME}/.pwnm/templates/mcp-config"

# Get MCP configuration path
# Returns the path to the MCP configuration file
get_mcp_config() {
    if [ -f "${MCP_CONFIG_TEMPLATE}" ]; then
        echo "${MCP_CONFIG_TEMPLATE}"
        return 0
    else
        log_error "MCP 配置文件不存在: ${MCP_CONFIG_TEMPLATE}"
        return 1
    fi
}

# Check MCP server availability
check_mcp_servers() {
    log_info "检查 MCP 配置文件..."

    if [ -f "${MCP_CONFIG_TEMPLATE}" ]; then
        log_success "MCP 配置文件存在: ${MCP_CONFIG_TEMPLATE}"

        # Extract and check IDA MCP URL if available
        local ida_url=$(jq -r '.mcpServers.IDAPro.url // empty' "${MCP_CONFIG_TEMPLATE}" 2>/dev/null)
        if [ -n "$ida_url" ]; then
            if curl -s --connect-timeout 3 --max-time 5 -I -f "${ida_url}" &> /dev/null; then
                log_success "IDA MCP 服务器可访问: ${ida_url}"
            else
                log_warning "IDA MCP 服务器不可访问: ${ida_url}"
            fi
        fi

        # Check GDB MCP command if available
        local gdb_command=$(jq -r '.mcpServers.gdb.command // empty' "${MCP_CONFIG_TEMPLATE}" 2>/dev/null)
        if [ -n "$gdb_command" ]; then
            if [ -f "${gdb_command}" ]; then
                log_success "GDB MCP 命令文件存在: ${gdb_command}"
            else
                log_warning "GDB MCP 命令文件不存在: ${gdb_command}"
            fi
        fi
    else
        log_error "MCP 配置文件不存在: ${MCP_CONFIG_TEMPLATE}"
        return 1
    fi
}

# Initialize solve directory
# Args: $1 = solve directory path
init_solve_dir() {
    local solve_dir="$1"

    log_step "初始化 solve 目录..."

    if [ -d "${solve_dir}" ]; then
        log_warning "solve 目录已存在: ${solve_dir}"
    else
        mkdir -p "${solve_dir}"
        log_success "solve 目录已创建: ${solve_dir}"
    fi

    # Create flag file
    cat > "./solve/flag" <<'FLAGEOF'
flag{adfsd-dasfdsf-fbawds-adfsa}
FLAGEOF

    cat > "./flag" <<'FLAGEOF'
flag{adfsd-dasfdsf-fbawds-adfsa}
FLAGEOF
}

# Call Claude Code
# Args:
#   $1 = Prompt
#   $2 = MCP config file path
#   $3 = Output file path
#   $4 = session_id (optional, for resuming session)
#   $5 = session_file path (optional, for early session_id writing)
call_claude() {
    local prompt="$1"
    local mcp_config_file="$2"
    local output_file="$3"
    local session_id="$4"
    local session_file="$5"

    log_step "调用 Claude Code..."

    # Escape prompt using printf %q
    local escaped_prompt=$(printf %q "$prompt")

    # Build command
    local claude_cmd="claude -p $escaped_prompt --allowedTools '*' --permission-mode bypassPermissions --output-format stream-json --verbose --mcp-config '$mcp_config_file'"

    # Use --resume if session_id is provided
    if [ -n "$session_id" ]; then
        claude_cmd="$claude_cmd --resume '$session_id'"
        log_info "Resume 模式: Session ID = $session_id"
    fi

    # Display executing command
    echo "" >&2

    # Get format script path
    local format_script="${SCRIPT_DIR}/format_output.sh"

    # Create a temporary file for output
    local temp_output=$(mktemp)
    local session_extracted=0

    # Start background process to monitor and extract session_id in real-time
    if [ -n "$session_file" ] && [ -z "$session_id" ]; then
        (
            # Monitor temp_output file for session_id
            local retry_count=0
            local max_retries=60  # Wait up to 60 seconds
            while [ $retry_count -lt $max_retries ] && [ ! -f "${temp_output}.done" ]; do
                if [ -f "$temp_output" ]; then
                    local sid=$(jq -r 'select(.session_id != null) | .session_id' "$temp_output" 2>/dev/null | head -n 1)
                    if [ -n "$sid" ] && [ "$sid" != "null" ] && [ ! -f "${session_file}" ]; then
                        echo "$sid" > "$session_file"
                        log_info "Session ID 已保存: $sid"
                        break
                    fi
                fi
                sleep 1
                retry_count=$((retry_count + 1))
            done
        ) &
        local monitor_pid=$!
    fi

    # Execute and process output through format script
    # Raw output saved to temp file first, formatted output to terminal
    if [ -f "$format_script" ]; then
        eval "$claude_cmd" 2>&1 | tee "$temp_output" | "$format_script"
        local exit_code=${PIPESTATUS[0]}
    else
        # Fallback to raw output if format script doesn't exist
        eval "$claude_cmd" 2>&1 | tee "$temp_output"
        local exit_code=${PIPESTATUS[0]}
    fi

    # Signal that claude execution is done
    touch "${temp_output}.done"

    # Wait for background monitor to finish
    if [ -n "$monitor_pid" ]; then
        wait $monitor_pid 2>/dev/null || true
    fi

    echo "" >&2
    if [ $exit_code -ne 0 ]; then
        log_error "Claude Code 执行失败，退出码: $exit_code"
        rm -f "$temp_output" "${temp_output}.done"
        return 1
    fi

    # Move temp output to final location
    cat "$temp_output" >> "$output_file"

    # # Ensure session_id is saved (fallback if background process didn't catch it)
    # if [ -n "$session_file" ] && [ -z "$session_id" ] && [ ! -f "$session_file" ]; then
    #     local sid=$(jq -r 'select(.session_id != null) | .session_id' "$temp_output" 2>/dev/null | head -n 1)
    #     if [ -n "$sid" ] && [ "$sid" != "null" ]; then
    #         echo "$sid" > "$session_file"
    #         log_info "Session ID 已保存: $sid"
    #     fi
    # fi

    rm -f "$temp_output" "${temp_output}.done"
    return 0
}

# Extract session_id
# Args: $1 = JSON output file
extract_session_id() {
    local json_file="$1"

    if [ ! -f "$json_file" ]; then
        return 1
    fi

    # Extract first session_id
    local session_id=$(jq -r 'select(.session_id != null) | .session_id' "$json_file" 2>/dev/null | head -n 1)

    if [ -n "$session_id" ] && [ "$session_id" != "null" ]; then
        echo "$session_id"
        return 0
    fi

    return 1
}
