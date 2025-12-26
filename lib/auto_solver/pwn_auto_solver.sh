#!/usr/bin/env bash
# Author: starrysky
# Contributor: Rimuawa
# Description: PWN auto-solver main entry point

set -e  # Exit on error

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load dependency libraries
source "${SCRIPT_DIR}/ai_solver.sh"
source "${SCRIPT_DIR}/ai_prompts.sh"

main() {
    local pwn_file=""
    local custom_desc=""
    local work_dir=""
    local resume_session=""
    local custom_prompt=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--file)
                pwn_file="$2"
                shift 2
                ;;
            -d|--description)
                custom_desc="$2"
                shift 2
                ;;
            --resume)
                resume_session="$2"
                shift 2
                ;;
            -p|--prompt)
                custom_prompt="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # If no file specified, try to find pwn file in current directory
    if [ -z "$pwn_file" ]; then
        if [ -f "./pwn" ]; then
            pwn_file="./pwn"
            log_info "未指定题目文件，使用当前目录的 pwn 文件"
        else
            log_error "请指定题目文件: -f <pwn_file>"
            show_help
            exit 1
        fi
    fi

    # Check if file exists
    if [ ! -f "$pwn_file" ]; then
        log_error "题目文件不存在: $pwn_file"
        exit 1
    fi

    # Get absolute path
    pwn_file="$(cd "$(dirname "$pwn_file")" && pwd)/$(basename "$pwn_file")"
    work_dir="$(dirname "$pwn_file")"

    # Define solve directory
    local solve_dir="${work_dir}/solve"

    # Display task information
    echo ""
    log_step "PWN Auto Solver 启动"
    [ -n "$custom_desc" ] && log_info "题目描述: ${custom_desc}"
    echo ""

    # Check dependencies
    if ! command -v claude &> /dev/null; then
        log_error "命令 'claude' 未找到，请先安装 Claude Code"
        exit 1
    fi

    if ! command -v jq &> /dev/null; then
        log_error "命令 'jq' 未找到，请先安装"
        exit 1
    fi

    # Check MCP servers
    check_mcp_servers
    echo ""

    # Initialize solve directory
    init_solve_dir "$solve_dir"
    echo ""

    # Define output files
    local output_file="${solve_dir}/solve_output.json"
    local session_file="${solve_dir}/session_id"

    # Get MCP configuration file path
    local mcp_config_file
    if ! mcp_config_file=$(get_mcp_config); then
        log_error "无法获取 MCP 配置文件"
        exit 1
    fi

    # Build prompt (use custom prompt if in resume mode, otherwise build initial prompt)
    local prompt
    if [ -n "$resume_session" ]; then
        if [ -n "$custom_prompt" ]; then
            prompt="$custom_prompt"
        else
            prompt="继续分析"
        fi
    else
        prompt=$(build_initial_prompt "$pwn_file" "$work_dir" "$solve_dir" "$custom_desc")
    fi
    echo ""

    # Call Claude Code (pass resume_session if provided)
    local session_to_use=""
    local session_file_arg=""

    if [ -n "$resume_session" ]; then
        session_to_use="$resume_session"
    else
        # Pass session_file for early writing in new sessions
        session_file_arg="$session_file"
    fi

    if ! call_claude "$prompt" "$mcp_config_file" "$output_file" "$session_to_use" "$session_file_arg"; then
        log_error "Claude Code 执行失败"
        exit 1
    fi

    # Extract and save session_id (if new session)
    local session_id
    if [ -z "$resume_session" ]; then
        session_id=$(extract_session_id "$output_file")
        if [ -n "$session_id" ]; then
            echo "$session_id" > "$session_file"
            echo ""
            log_success "Session ID: $session_id"
            log_info "Session ID 已保存到: $session_file"
        else
            log_warning "未能提取 session_id"
        fi
    else
        session_id="$resume_session"
    fi

    # Generate Markdown report
    local report_file="${solve_dir}/analysis_report.md"
    local report_script="${SCRIPT_DIR}/generate_report.sh"

    echo ""
    log_step "生成分析报告..."

    if [ -f "$report_script" ]; then
        # Append mode if resuming, otherwise create new
        if [ -n "$resume_session" ]; then
            if "$report_script" "$output_file" "$report_file" --append 2>&1; then
                log_success "Markdown 报告已追加: $report_file"
            else
                log_warning "Markdown 报告生成失败"
            fi
        else
            if "$report_script" "$output_file" "$report_file" 2>&1; then
                log_success "Markdown 报告已生成: $report_file"
            else
                log_warning "Markdown 报告生成失败"
            fi
        fi
    else
        log_warning "报告生成脚本不存在，跳过"
    fi

    log_info "完整输出已保存到: $output_file"

    rm -rf /tmp/claude*
}

# Show help information
show_help() {
    cat <<EOF
PWN Auto Solver - AI 自动解题工具

用法:
    pwn_auto_solver.sh [选项]

选项:
    -f, --file <path>          指定题目文件路径（默认: ./pwn）
    -d, --description <text>   题目描述（可选）
    --resume <session_id>      恢复已有会话继续分析
    -p, --prompt <text>        自定义提示词（仅在 resume 模式下使用）
    -h, --help                 显示此帮助信息

示例:
    # 使用当前目录的 pwn 文件
    pwn_auto_solver.sh

    # 指定题目文件
    pwn_auto_solver.sh -f /path/to/pwn

    # 指定题目文件和描述
    pwn_auto_solver.sh -f ./pwn -d "简单的栈溢出题目"

    # 恢复已有会话继续分析
    pwn_auto_solver.sh --resume <session_id> -p "继续分析漏洞利用"

继续分析:
    执行完成后，可以使用保存的 session_id 继续对话:

    claude --resume <session_id>

    或者从文件读取:

    claude --resume \$(cat solve/session_id)

    或者使用 pwnm auto 命令自动管理会话
EOF
}

# Execute main function
main "$@"
