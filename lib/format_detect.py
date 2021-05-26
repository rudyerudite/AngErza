from pwn import *
import r2pipe
import re
import angr
import claripy

function = {}

def check_fmt(binary):
	function = findfunctions(binary)
	fmt_fun = ["printf"]

	findfunctions(binary)
	p = process(binary)
	r = r2pipe.open(binary,flags = ["-d"])
	i = 0
	inpsize = 0
	fmt_fns = list((set(function.keys())).intersection(fmt_fun))
	#print(stdin_fns)
	for fn in stdin_fns:
		log.info("Continuing until {}".format(hex(function[fn])))
		r.cmd('db {}'.format(hex(function[fn])))
		r.cmd('dc')
		rdi = r.cmd('dr rdi')
		rsi = r.cmd('dr rsi')
		print(rdi,rsi)
        if(rdi )
        #Not sure how to check the number of arguments for printf
        #If rdi value is writeable, then print out that fmt detected
		