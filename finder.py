#!/usr/bin/env python3

from pwn import *
import claripy
import angr

proj = angr.Project("bug",auto_load_libs=False)
binary = ELF("bug")

properties = {}
gets = proj.loader.find_symbol('gets')
print(gets)

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



