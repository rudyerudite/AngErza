from pwn import *
import r2pipe
import angr
import claripy

def format_string_detect(binary,function):
	output_functions = ["printf"]
	
	p = process(binary)
	r = r2pipe.open(binary)
	r.cmd('e dbg.profile=profile.rr2')
	r.cmd('ood') 
	i = 0
	inpsize = 0
	printf_fns = list((set(function.keys())).intersection(output_functions))
	print(printf_fns)
	for fn in printf_fns:
		log.info("Continuing until {}".format(hex(function[fn])))
		r.cmd('db {}'.format(hex(function[fn])))
		r.cmd('dc')
		rdi = r.cmd('dr rdi')
		rsi = r.cmd('dr rsi')
		rdx = r.cmd('dr rdx')
		rbp = r.cmd('dr rbp')
		print(rdi,rsi,rdx,rbp)
		print(r.cmd('drr~rdi'))

	#local --> stack addr where bof is possible, size_array --> accounting for size of the overflows
	return 
