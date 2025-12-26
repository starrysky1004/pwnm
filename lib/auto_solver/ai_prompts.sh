#!/usr/bin/env bash
# Author: starrysky
# Contributor: Rimuawa
# Description: AI prompt templates for PWN challenge solving

# Common PWN solving prompt template
get_common_pwn_prompt() {
    cat <<'EOF'
你是一名专业的 CTF PWN 选手，现在需要解决一道 PWN 题目，你的目标是读取 flag 文件（与程序在同一目录）中的内容。

## 解题流程
1. 阅读参考资料中的解题策略文件和 exp 模板文件
2. 使用 checksec 检查保护机制
3. 使用 IDAPro MCP 分析反编译代码并识别可能存在的漏洞（堆栈溢出、格式化字符串漏洞、UAF、整数溢出等）
4. 在 solve 目录下使用 pwntools 库编写 exp 脚本进行漏洞利用
5. 测试漏洞利用脚本，同时可以使用多种工具辅助调试和 exp 编写，包括但不限于 GDB MCP / ROPgadget / z3 / seccomp-tools / one_gadget

## 重要约束
- ⚠️ **只能在 solve/ 目录创建/修改文件**
- ⚠️ solve/ 之外的文件只能查看，不能修改

## 输出要求
- 详细记录分析过程和思路，说明每一步的目的和结果
- 遇到问题时描述并尝试解决，最终输出 flag 与解题分析总结或说明失败原因
EOF
}

# Build complete initial prompt
# Args:
#   $1 = Challenge file path
#   $2 = Working directory
#   $3 = Solve directory
#   $4 = Custom challenge description (optional)
build_initial_prompt() {
    local pwn_file="$1"
    local work_dir="$2"
    local solve_dir="$3"
    local custom_desc="$4"
    local template_dir="$HOME/.pwnm/templates"

    cat <<EOF
$(get_common_pwn_prompt)

## 当前任务
- 题目文件: ${pwn_file}
- 工作目录: ${work_dir}
- solve 目录: ${solve_dir}
$([ -n "$custom_desc" ] && echo "- 题目描述: ${custom_desc}")

## 参考资料
- 解题策略: ${template_dir}/strategy.md
- Exploit 模板: ${template_dir}/exp.py

请先阅读上述两个文件了解解题流程和代码模板，然后开始解题！
EOF
}
