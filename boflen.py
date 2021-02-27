from pwn import *
import r2pipe
import re
import angr
import claripy

input_functions = ["read","fgets","gets","__isoc99_scanf"]
binary =  sys.argv[1]
function = {}
overflow = 0
size = 0
def findfunctions(name):
# reference: https://docs.angr.io/built-in-analyses/identifier
# functionality to find the different libc functions in the code
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
	if(fn=="fgets" or fn=="read"):
		if(fn == "fgets"):
			size = int(rbp,16)-int(rdi,16)
			inpsize = int(rsi,16)
		elif(fn == "read"):
			size = int(rbp,16)-int(rsi,16)
			inpsize = int(rdx,16)
		if(size < inpsize ):
			overflow = inpsize-size
			lof.info("BOF found size: {}".format(overflow))
	elif(fn=="gets"):
		overflow = 256
		log.info("[+] gets found")
	elif(fn=="__isoc99_scanf"):
		m = r.cmd('psz @rdi')
		# doesn't check for %ms type args where m > size of the buf
		if("%s" in m):
			overflow = 256
			log.info("[+] overflow in scanf found")

return overflow 





