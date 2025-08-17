from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './pwn'

context.terminal = ['tmux','splitw','-h']

debug = 0
if debug:
    r = remote('node4.buuoj.cn', 26870)
else:
    r = process(file_name)

elf = ELF(file_name)

def dbg():
    gdb.attach(r)

r.interactive()
