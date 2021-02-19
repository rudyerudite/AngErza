from pwn import *
import r2pipe
import re
import angr
import claripy

input_functions = ["read","fgets","gets","scanf"]
binary =  sys.argv[1]
function = {}

def findfunctions(name):
	proj = angr.Project(name,auto_load_libs=False)
	state = proj.factory.entry_state(stdin=angr.SimFile)
	id_ = proj.analyses.Identifier()
	for fninfo in id_.func_info:
		print(hex(fninfo.addr), fninfo.name)
		function[fninfo.name] = fninfo.addr
findfunctions(binary)
p = process(binary)
r = r2pipe.open(binary,flags = ["-d"])

stdin_fns = list((set(function.keys())).intersection(input_functions))
print(stdin_fns)
for fn in stdin_fns:
	log.info("Continuing until {}".format(hex(function[fn])))
	r.cmd('db {}'.format(hex(function[fn])))
	r.cmd('dc')
	rdi = r.cmd('dr rdi')
	rsi = r.cmd('dr rsi')
	rdx = r.cmd('dr rdx')
	rbp = r.cmd('dr rbp')
	print(rdi,rsi,rdx,rbp)
