from pwn import *
import r2pipe
import re
import angr
import claripy

function = {}

def findmitigation(binary,properties):
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
	binary = ELF(binary)
	properties['aslr'] = binary.aslr
	properties['arch'] = binary.arch
	properties['canary'] = binary.canary
	properties['got'] = binary.got
	properties['nx'] = binary.nx
	properties['pie'] = binary.pie
	properties['plt'] = binary.plt
	properties['relro'] = binary.relro

	return properties

def findfunctions(name):
# reference: https://docs.angr.io/built-in-analyses/identifier
# functionality to find the different libc functions in the code
	global function
	proj = angr.Project(name,auto_load_libs=False)
	state = proj.factory.entry_state(stdin=angr.SimFile)
	id_ = proj.analyses.Identifier()
	for fninfo in id_.func_info:
		print(hex(fninfo.addr), fninfo.name)
		function[fninfo.name] = fninfo.addr
	return function

def find_win(simgr):
	# finding win functions in the binary and trying to call it
	# incomplete and failed implementation of the above
	win_addr = 0x0000
	if ("system" in function): 
		win_addr = function["system"]
		simgr.explore(find = win_addr)
		if simgr.found:
			sol = simgr.found[0]
			print(sol.posix.dumps(0))
			print("woooooooooooooooooooooooooooooooooooooooooooooooooooow")
		else:
			print("noooooooooooooooooooooooooooooooooo")
	return win_addr

def stdin_fn(binary):
	function = findfunctions(binary)
	input_functions = ["read","fgets","gets","__isoc99_scanf"]
	
	size_array = []
	size = 0

	local = []
	overflow = 0
	findfunctions(binary)
	p = process(binary)
	r = r2pipe.open(binary,flags = ["-d"])
	i = 0
	inpsize = 0
	stdin_fns = list((set(function.keys())).intersection(input_functions))
	#print(stdin_fns)
	for fn in stdin_fns:
		log.info("Continuing until {}".format(hex(function[fn])))
		r.cmd('db {}'.format(hex(function[fn])))
		r.cmd('dc')
		rdi = r.cmd('dr rdi')
		rsi = r.cmd('dr rsi')
		rdx = r.cmd('dr rdx')
		rbp = r.cmd('dr rbp')
		print(rdi,rsi,rdx,rbp)
		if(fn=="fgets" or fn=="read"):
			if(fn == "fgets"):
				size = int(rbp,16)-int(rdi,16)
				inpsize = int(rsi,16)
			elif(fn == "read"):
				size = int(rbp,16)-int(rsi,16)
				inpsize = int(rdx,16)
			if(size < inpsize ):
				overflow = inpsize-size
				i+=1
				log.info("BOF found size: {}".format(overflow))
			else:
				overflow = 0
		elif(fn=="gets"):
			size = int(rbp,16)-int(rdi,16)
			overflow = 256
			inpsize = 256
			log.info("[+] gets found")
		elif(fn=="__isoc99_scanf"):
			m = r.cmd('psz @rdi')
		# doesn't check for %ms type args where m > size of the buf
			if("%s" in m):
				inpsize = 256
				overflow = 256
				log.info("[+] overflow in scanf found")
	
		if(overflow!=0):
			local.append(claripy.BVS('local'+str(i),inpsize*8))
			size_array.append(overflow)
			i+=1
		overflow = 0
	#local --> stack addr where bof is possible, size_array --> accounting for size of the overflows
	return local,size_array,size
#how to add a check to find if there's an internal buffer overflow; where we can overflow one buffer and then corrupt the nearby variables
#can rbp corruption cause any issue?
#using radare to see which all local variables are declared and then finding their size
#r.cmd('aa')
#print(r.cmd('afvd'))
