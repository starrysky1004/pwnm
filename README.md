

# ![logo](images/logo.png) 

✨ **让 PWN 题目管理变得简单** ✨

一个 PWN 题管理工具，支持自动化环境配置、题目分类、信息管理和 Claude 自动解题 (ﾉ◕ヮ◕)ﾉ*:･ﾟ✧

---

## 📦 安装要求

1. 如果需要**自动搭建环境**，需要先更新系统：

   ```shell
   sudo apt update && sudo apt upgrade -y
   ```

2. claude 及 mcp 需要自己配环境并且测试可用性，推荐使用 [GDB-MCP](https://github.com/smadi0x86/gdb-mcp)，IDA Pro mcp 可以使用 idalib 或直接把 windows 里 mcp 脚本里的 host 改成 0.0.0.0

3. 安装前可以修改 templates 中的 exp 模板和 mcp-config，并且在 Pwn 文件夹存放知识库，也可以在安装完成后修改 ~/.pwnm/templates 中的对应文件

---

## 🚀 快速开始

```bash
git clone https://github.com/starrysky1004/pwnm.git
cd pwnm
source pwnm.sh
pwnm init
```

初始化过程会询问：

**🤔 是否需要自动搭建 PWN 环境？(y/n)**
- 选择 `y`: 自动配置 PWN 环境，其中 `glibc-all-in-one` 默认安装到家目录 (`~/glibc-all-in-one`)
- 选择 `n`: 需要手动指定 `glibc-all-in-one` 路径 (直接回车默认: `~/glibc-all-in-one`)

**📂 请输入 PWN 题目存储路径:**

- 这里存放所有比赛和题目文件夹 (直接回车默认: ~/pwn_challenge)

初始化完成后，会在家目录创建 `~/.pwnm` 文件夹，包含：
- 📋 `templates/` - 模板文件 (exp.py, AwdPwnPatcher 等)
- ⚙️ `config` - 配置文件
- 📊 `index.tsv` - 题目信息索引

---

## 📚 功能详解

### 🎨 初始化环境

#### `pwnm init`

初始化 PWNM 工作环境 ✨

**功能包括：**
- 🏗️ 创建题目存储目录
- 📥 安装必要的依赖工具 (`jq`, `fzf`, `binutils`)
- 🔧 配置 `glibc-all-in-one` 路径
- 📝 复制模板文件到 `~/.pwnm/templates/`
- 🔗 添加 Shell 集成

**自动搭建模式 (y)：**
- 安装常用 PWN 工具
- 配置 Python 环境和 pwntools

**手动配置模式 (n)：**
- 需要手动指定 `glibc-all-in-one` 路径

---

### 📁 比赛与题目管理

#### `pwnm new <比赛名称>`

创建新的比赛文件夹 🎪

```bash
pwnm new XCTF2024
# 创建 ~/pwn_challenge/XCTF2024/
```

#### `pwnm ls`

列出所有已创建的比赛文件夹 📋

```bash
pwnm ls
# 输出:
# XCTF2024
# VNCTF2024
# ...
```

#### `pwnm cd <比赛名称>`

快速进入指定比赛文件夹 🚀

```bash
pwnm cd XCTF2024
# cd ~/pwn_challenge/XCTF2024
```

支持模糊匹配，不用输入完整名称～

---

#### `pwnm add <题目名称> [--awd | --awdp]`

在**比赛文件夹下**创建题目文件夹 📝

**基础模式：**

```bash
pwnm add baby_pwn
```

**自动执行：**
- 📂 创建 `baby_pwn/` 文件夹
- 📄 复制 `exp.py` 模板
- 📂 自动打开文件管理器 (方便拖入题目文件)
- ✏️ 自动打开 Vim 编辑 `exp.py`
- 📊 初始化题目元数据 (`.pwnm/meta.json`)

**AWD 模式：**

```bash
pwnm add baby_pwn --awd
```

**额外包含：**
- 🛠️ `AwdPwnPatcher/` - PWN 补丁工具
- 🤖 `awdpwn/` - PWN 自动攻击脚本

> ⚠️ **提示**: 打补丁前记得备份原程序哟 w

**AWDP 模式：**

```bash
pwnm add baby_pwn --awdp
```

**额外包含：**
- 🛠️ `AwdPwnPatcher/` - PWN 补丁工具
- 📦 `result/` - 补丁结果目录
  - 包含 `update.sh` 脚本
  - 可使用 `pwnm pack` 打包为 `update.tar.gz` 并自动打开文件夹

---

### 🔍 安全检查与配置

#### `pwnm cs <二进制文件>`

对二进制文件执行安全检查 🔐

```bash
pwnm cs challenge
```

**自动执行：**
- ✅ 运行 `checksec` 检查保护机制
- 📊 提取并保存保护信息 (RELRO, Canary, NX, PIE)
- 🏗️ 识别架构 (amd64, i386 等)
- 🔄 自动重命名为 `pwn` 并赋可执行权限(匹配 exp.py 中的默认文件名)
- 💾 更新题目元数据

---

#### `pwnm gl <libc文件> [二进制文件]`

从 `glibc-all-in-one` 自动替换 libc 和 ld 🔧

```bash
# 使用默认二进制文件名 (pwn)
pwnm gl ./libc-2.31.so
pwnm gl ~/glibc-all-in-one/libs/2.39-0ubuntu8_amd64/libc.so.6

# 指定二进制文件
pwnm gl ./libc-2.31.so ./challenge
```

**自动执行：**
- 🔍 从 libc 文件中识别版本号
- 📦 在 `glibc-all-in-one/libs/` 中查找匹配的库
- 📋 复制对应的 `libc.so.6` 和 `ld-*.so` 到当前目录并赋可执行权限
- 🔗 使用 `patchelf` 修改二进制文件的链接
- 💾 自动备份原始二进制文件 (`.bak` 后缀)
- ✅ 验证替换结果

**输出示例：**

```
[INFO] libc版本解析成功<(^-^)>: 2.31-0ubuntu9.17
[SUCCESS] 已备份为: ./pwn.bak
[SUCCESS] 成功替换 pwn 文件 libc/ld √
[INFO] Interpreter: ./ld-2.31.so
[INFO] Needed: ./libc.so.6
```

---

### 🏷️ 标签与信息管理

#### `pwnm t <tag1> [t <tag2> ...]`

为当前题目添加标签 🏷️

```bash
# 单个标签
pwnm t heap

# 多个标签
pwnm t heap t tcache t double-free

# 标签可包含空格 (以 t 分隔)
pwnm t heap overflow t use after free
```

**特性：**
- ✨ 标签自动去重
- 💾 自动更新题目索引
- 🔍 支持空格标签 (使用 `t` 作为分隔符)

---

#### `pwnm unset <libc|tag>`

清除题目的 libc 或标签信息 🗑️

```bash
# 清除 libc 信息
pwnm unset libc

# 清除所有标签
pwnm unset tag
```

---

#### `pwnm i` / `pwnm info`

查看当前题目的详细信息 📊

```bash
pwnm i
```

**输出示例：**

```json
{
  "contest": "XCTF2024",
  "problem": "baby_pwn",
  "workdir": "/home/user/pwn_challenge/XCTF2024/baby_pwn",
  "libc": "2.31-0ubuntu9.17",
  "arch": "amd64",
  "endian": "little",
  "protections": {
    "RELRO": "Partial RELRO",
    "CANARY": "Canary found",
    "NX": "NX enabled",
    "PIE": "No PIE"
  },
  "type": "heap, tcache, double-free",
  "tags": ["heap", "tcache", "double-free"],
  "created_at": "2024-01-15 14:30:00"
}
```

---

### 🔎 题目搜索

#### `pwnm st` / `pwnm search`

可视化搜索和筛选题目 🔍✨

```bash
pwnm st
```

**功能：**
- 📋 列出所有题目及其信息
- 🔍 基于 `fzf` 的交互式搜索
- 🎯 支持模糊匹配 (比赛名、题目名、libc 版本、标签等)
- ✅ 多选支持 (使用 `Tab` 键)
- 🚀 选中后按 `Enter` 直接进入题目目录

**显示列：**

| 比赛名称 | 题目名称 | Libc | Arch | RELRO | Canary | NX | PIE | 题目类型 | 创建时间 |
|---------|---------|------|------|-------|--------|----|----|---------|---------|

**使用技巧：**
- 输入关键词快速筛选 (如: `heap`, `2.31`, `XCTF`)
- `Enter` 进入选中的题目目录

---

### 🤖 AI 自动解题

#### `pwnm auto`

使用 Claude AI 自动分析和解题 🤖✨

> **⚠️ 前置要求：**
> - 已安装 [Claude Code CLI](https://claude.ai/claude-code) 并登陆
> - 已配置 MCP 服务器

---

**📝 首次运行 (无 session)：**

```bash
pwnm auto
```

**交互流程：**

1️⃣ **输入题目文件名：**
```
[INFO] 请输入题目文件名 (直接回车默认为 pwn):
> pwn
```

2️⃣ **输入题目描述 (可选)：**
```
[INFO] 请输入题目描述 (直接回车跳过):
> 简单的栈溢出题目
```

3️⃣ **AI 自动分析：**
- 🔍 自动分析二进制文件
- 🛡️ 检查保护机制
- 🐛 查找漏洞点
- 💡 生成 exploit 脚本
- 📝 生成分析报告

4️⃣ **保存会话：**
- Session ID 自动保存到 `solve/session_id`
- 完整输出保存到 `solve/solve_output.json`
- 分析报告保存到 `solve/analysis_report.md`

---

**🔄 继续已有会话：**

```bash
pwnm auto
```

**检测到已有 session 时：**

```
[INFO] 检测到已存在的 AI 会话: sess_abc123xyz
[INFO] 是否需要与当前 session 进行对话？(y/n)
```

**选项 1: 直接对话 (y)**
```
> y
[INFO] 启动 AI 对话...
# 进入 Claude Code 交互式会话
```

**选项 2: 继续自动分析 (n)**
```
> n
[INFO] 请输入题目文件名 (直接回车默认为 pwn):
> pwn
[INFO] 请输入新的分析指令:
> 帮我分析一下堆漏洞的利用方法
```

---

**💡 AI 解题特性：**
- ✅ **实时 Session 保存** - 在 Claude 运行时立即写入 session_id
- ✅ **会话恢复** - 支持中断后继续对话
- ✅ **自定义指令** - 可指定特定分析任务
- ✅ **MCP 集成** - 支持 IDA Pro MCP 和 GDB MCP
- ✅ **完整日志** - 所有交互记录保存为 JSON
- ✅ **Markdown 报告** - 自动生成可读的分析报告

---

**🎯 使用示例：**

```bash
# 进入题目目录
cd ~/pwn_challenge/XCTF2024/baby_heap

# 启动 AI 自动解题
pwnm auto
> pwn
> 这是一个堆溢出题目，需要利用 tcache poisoning

# 等待 AI 分析...
# [AI 分析过程] 检查保护 -> 反编译 -> 查找漏洞 -> 生成 exp

# 查看生成的报告
cat solve/analysis_report.md

# 继续对话
pwnm auto
> y  # 选择直接对话
> 能否详细解释一下利用链？

# 或者指定新任务
pwnm auto
> n  # 不直接对话
> pwn
> 帮我写一个完整的 exploit 脚本
```

---

### 📦 AWD 专用功能

#### `pwnm pack`

在 `result/` 目录下打包补丁文件 📦

**使用场景：** AWDP 模式下，打完补丁后需要提交

**前置条件：** 必须在 `result/` 目录下执行

```bash
cd ~/pwn_challenge/XCTF2024/baby_pwn/result
pwnm pack
```

**自动执行：**
- 📦 将当前目录所有文件打包为 `update.tar.gz`
- 📂 自动打开文件管理器，方便从虚拟机拖出文件

**输出：**
```
[SUCCESS] 打包成功ovo: /path/to/result/update.tar.gz
```

---

#### `pwnm open [目录]`

打开文件管理器 📂

```bash
# 打开当前目录
pwnm open

# 打开指定目录
pwnm open ~/pwn_challenge/XCTF2024
```

---

### 🔧 修改 exp 模板

可以修改 `~/.pwnm/templates/` 下的模板文件：

```bash
# 编辑 exp.py 模板
vim ~/.pwnm/templates/exp.py
```

---

### 📊 题目索引数据库

所有题目信息存储在 `~/.pwnm/index.tsv`：

```tsv
比赛名称  题目名称  路径  Libc  Arch  RELRO  Canary  NX  PIE  类型  创建时间
XCTF2024  baby_heap  /home/user/pwn_challenge/XCTF2024/baby_heap  2.31  amd64  Partial  Yes  Yes  No  heap,tcache  2024-01
```

---

### 🔍 题目元数据

每个题目的 `.pwnm/meta.json` 存储详细信息：

```json
{
  "contest": "XCTF2024",
  "problem": "baby_heap",
  "workdir": "/home/user/pwn_challenge/XCTF2024/baby_heap",
  "libc": "2.31-0ubuntu9.17",
  "arch": "amd64",
  "endian": "little",
  "protections": {
    "RELRO": "Partial RELRO",
    "CANARY": "Canary found",
    "NX": "NX enabled",
    "PIE": "No PIE"
  },
  "type": "heap, tcache, double-free",
  "tags": ["heap", "tcache", "double-free"],
  "created_at": "2024-01-15 14:30:00"
}
```

---

## 📜 更新日志

### v1 (2025-08-18)

- ✨ 初始版本发布
- 🎯 支持题目管理和分类
- 🔧 自动 libc/ld 替换
- 🏷️ 题目标签
- 🔍 可视化搜索
- 📦 AWD/AWDP 支持

### v2 (2025-12-23)

- 支持新版本 checksec
- 支持含有空格的标签
- 🤖 AI 自动解题集成
- 解决打开文件夹 code 与 VS code 冲突
- 支持清空 libc 和 tag 信息
- 自动配置 pwn 环境

---

**🌟 如果觉得有用，请给个 Star 吧！ 🌟**

Made with ❤️ by [starrysky1004](https://github.com/starrysky1004) & [Rimuawa](https://github.com/Rimuawa)

٩(◕‿◕｡)۶ **Happy Pwning!** (ﾉ◕ヮ◕)ﾉ*:･ﾟ✧
