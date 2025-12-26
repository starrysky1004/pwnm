# PWN 解题指南

## 任务目标
分析并利用 PWN 漏洞，通过获取 shell 或直接读取文件的形式，获取程序所在目录的 flag 文件的内容

## 可用工具

### 1. IDAPro MCP
- 获取反编译代码、函数列表
- 分析漏洞函数和危险操作
- 工具: `mcp__ida__*` 系列函数

### 2. GDB MCP
- 动态调试、内存查看、断点设置
- 工具: `mcp__gdb__*` 系列函数

### 3. 基础工具
- checksec: 检查二进制保护
- ROPgadget/ropper: 查找 ROP gadgets
- pwntools: 编写 exploit
- seccomp-tools：检查程序沙箱情况
- one_gadget：获取可用 gadgets
- strings：获取程序可见字符

## 常见漏洞类型

1. **栈溢出**: 覆盖返回地址
2. **堆溢出**: 破坏堆结构
3. **格式化字符串**: 任意读写
4. **UAF**: Use After Free
5. **整数溢出**: 超过变量类型最大值导致溢出
6. **伪随机数**: 可预测 rand() 序列

## 常用技巧模板

### 伪随机数处理

**代码模板:**
```python
from ctypes import CDLL, cdll
libc = cdll.LoadLibrary("libc.so.6")

# 以时间为种子 (禁止使用 time 库 time.time() 获取时间)
seed = libc.time(0)
# 或以固定数值为种子
seed = 0

libc.srand(seed)

# 获取随机数
v3 = libc.rand()
```

### 动态获取沙箱信息

当沙箱不是程序开始就开启的情况，可以使用以下方式动态运行 seccomp-tools 获取沙箱规则：

```python
r = process(["seccomp-tools", "dump", "./pwn"])
```

## 知识库

当你遇到不熟悉的漏洞类型或没有解题思路时，可以查阅 `~/.pwnm/template/Pwn` 目录下的知识库文档学习相关解题策略和技巧。

### 知识库目录结构

```
~/.pwnm/template/PWN

```

**注意**：知识库文档仅供学习参考，需要根据实际题目特点灵活应用。

