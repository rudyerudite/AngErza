#!/usr/bin/env python3

from pwn import *
import claripy
import angr

proj = angr.Project("./bug",auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFile)
binary = ELF("bug")
function = {}
properties = {}
unconstrained_input = False
len_unconstrained_input = -1
simgr = proj.factory.simulation_manager(state,save_unconstrained=True)
simgr.stashes['bof'] = []
crashing_input = ""

def findmitigation():
	# reference: https://github.com/ChrisTheCoolHut/Zeratool/blob/master/lib/protectionDetector.py
	# other trials
	'''
	if(proj.loader.main_object.execstack== True):
		print("NX is enabled")
	elif(proj.loader.main_object.pic == True):
		print("PIE is enabled")
	'''
	properties['aslr'] = binary.aslr
	properties['arch'] = binary.arch
	properties['canary'] = binary.canary
	properties['got'] = binary.got
	properties['nx'] = binary.nx
	properties['pie'] = binary.pie
	properties['plt'] = binary.plt
	properties['relro'] = binary.relro
	return properties

def findfunctions():
# reference: https://docs.angr.io/built-in-analyses/identifier
# functionality to find the different libc functions in the code
	id_ = proj.analyses.Identifier()
	for fninfo in id_.func_info:
		print(hex(fninfo.addr), fninfo.name)
		function[fninfo.name] = fninfo.addr

def find_bof(simgr):
	global crashing_input
# reference to the snippet idea: https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/buffer-overflows
	if len(simgr.unconstrained):
	# finding unconstrained path to overwrite the return address with "CCCC"*2
		for path in simgr.unconstrained:
			if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCC"*2]):
				path.add_constraints(path.regs.pc == b"CCCC"*2)
				if path.satisfiable():
					simgr.stashes['bof'].append(path)
					unconstrained_state = path
					crashing_input = unconstrained_state.posix.dumps(0)
					
				simgr.stashes['unconstrained'].remove(path)
				simgr.drop(stash='active')
	return simgr	

def prog_state(state):
# additional condition for gets as it is undetected in the search for unconstrained path
	if("gets" in function):
		unconstrained_input = True
		 # do something to reach till the input function and check for buffer size
		 # buffer_input_size > buffer_declared_size
	else:
		simgr.explore(step_func = find_bof)
		if(simgr.stashes['bof'] != []):
			print("[+] overflow detected")
			print("[+] len of crashing input {}".format(len(crashing_input)))

			if(binary.canary == False):
				print("[+] no canary detected")
			else:
				print("[+] canary detected")
		else:
			print("[+] no overflow detected")


		
findfunctions()
prog_state(state)






