from pwn import *
import angr
from lib import file_properties
from lib import boflen
from lib import exploitgen
from lib import shellcode_detect
from lib import format_string

binary = sys.argv[1]

proj = angr.Project(binary,auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFile)
simgr = proj.factory.simulation_manager(state,save_unconstrained=True)
#simgr.stashes['bof'] = []
properties = file_properties.file_parser(binary)
format_string = format_string.format_string_detect(binary,function)
local, size_array, size = boflen.stdin_fn(binary)
properties = boflen.findmitigation(binary,properties)
print(properties['nx'])
#win_addr = boflen.find_win(simgr)
if(size_array[0] == 0 and [properties['nx']] == 1):
    shellcode_detect.give_shell(size)
else:
    k = exploitgen.find_win_rop(size)
    if( k == ""):
        exploitgen.find_rop(size)

