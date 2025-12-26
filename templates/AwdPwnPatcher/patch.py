from AwdPwnPatcher import *

binary = "../pwn"
awd_pwn_patcher = AwdPwnPatcher(binary)

assembly = '''
mov rsi, rdi
mov rax, 0
mov rdx, 0xa
mov rdi, 0
syscall
'''

awd_pwn_patcher.patch_by_jmp(0x4017FF, jmp_to=0x401809, assembly=assembly)
awd_pwn_patcher.save()
