## pwnm · Pwn 比赛小工具 ✨

把日常比赛里重复又枯燥的活儿交给我吧！创建目录、检查保护、更换 libc、可视化筛选、便捷跳转、打包更新，一条龙～(ฅ˘ᵕ˘)ฅ 💖

---

### 安装 🚀

```bash
git clone https://github.com/starrysky1004/pwnm.git
```

---

### 初始化 🔧

```bash
# 可选：初始化前可替换 pwnm 目录中的 exp 和 awd 模板
cd pwnm

# 加载命令
source ~/pwnm/tools/pwnm.sh

# 让命令长期生效
source ~/.bashrc
# 或
source ~/.zshrc

# 指定题目根目录与 glibc-all-in-one 目录
# pwn_chal_dir 是用于存放所有比赛与题目的目录；glibc_all_in_one_dir 是本地的 glibc-all-in-one 仓库目录
pwnm init pwn_chal_dir glibc_all_in_one_dir
```

> [!CAUTION]
>
> 必须在 pwnm 目录下执行 init

---

### 日常使用 🍰

- **查看帮助信息**
  
  ```bash
  pwnm / pwnm help
  ```
  
- **创建比赛目录**：
  
  ```bash
  pwnm c competition_name
  ```
  
- **浏览所有比赛名**：
  
  ```bash
  pwnm l / pwnm ls
  ```
  
- **进入比赛目录（支持模糊匹配）**：
  
  ```bash
  pwnm g competition_name
  ```
  
- **创建题目目录**：
  
  ```bash
  pwnm n chal_name --awd     # AWD 模式
  pwnm n chal_name --awdp    # AWDP 模式
  ```
  - 自动创建题目目录，复制模板 `exp.py`到本目录下并打开`vim exp.py`
  - 按模式复制 `awd/awdp` 模板并打开题目文件夹用于拖放题目（`awdp` 的 `result/` 用于存放`patch`后的二进制与 `update.sh`）

  > [!WARNING]
  >
  > 只能在`pwnm c competition_name`创建的比赛文件夹下创建题目文件夹
  
- **检查保护机制**：
  ```bash
  pwnm cs binary_file
  ```
  - 使用 `checksec` 检查保护机制
  - 将文件名改为 `pwn` 以适配 `exp.py`（可按习惯修改源码`line:438-443`和`exp`脚本里的二进制文件名）
  - 保存保护机制信息至`.pwnm/meta.json`

- **自动提取 libc 版本与架构并替换**：
  
  ```bash
  pwnm gl libc_file
  ```
  - 根据`libcc`版本和架构从 `glibc_all_in_one` 找到匹配版本的 `libc` 与 `ld`
  - 复制到本地目录并替换 `pwn` 的 `libc/ld`（可改+1 `line:512`，需要与上一步同步修改为相同的文件名）
  - 保存 libc 信息至`.pwnm/meta.json`
  
- **查看题目信息**：
  
  ```bash
  pwnm i / pwnm info
  ```
  - 展示保护机制、libc 版本、架构、创建时间、比赛名、题目名
  
- **打tag**：
  
  ```bash
  # 在题目文件夹中执行，可多标签标记题型/考点
  pwnm t xxx
  ```
  
- **打包 update 文件夹（AWDP模式）**：
  
  ```bash
  # 在 awdp 模式的 result 文件夹下执行
  pwnm pack / pwnm upd
  ```
  
  - 需要先将 patch 后的二进制文件复制进 `result/`
  - 该指令将自动打包整个文件夹并打开压缩包所在目录，方便从虚拟机拖出压缩包
  
- **可视化筛选（fzf）**：
  
  ```bash
  pwnm st
  ```
  - 使用 `fzf` 展示所有题目的 `info`
  - 输入关键字即可模糊搜索，回车进入对应题目目录

---

### 依赖与环境 🧰

- 本工具仅自动安装 `jq fzf binutils`，其他正常写`pwn`题所需工具需自行安装，包括`checksec vim patchelf glibc-all-in-one`

---

### 开始你的 Pwn 之旅吧！🧭

```bash
pwnm c MyCTF
pwnm n easyheap --awd
pwnm cs ./heap
pwnm gl ./libc.so.6
pwnm i
pwnm t heap UAF
pwnm st
```

祝你比赛顺利，爆杀一切 (๑•̀ㅂ•́)و✧ ！
