from pwn import *
import angr
from lib import file_properties
from lib import boflen
from lib import exploitgen
from lib import shellcode_detect
<<<<<<< HEAD
from lib import format_string
=======
>>>>>>> d079517d21cdd80064bf1580dd4939e355344833

binary = sys.argv[1]

proj = angr.Project(binary,auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFile)
simgr = proj.factory.simulation_manager(state,save_unconstrained=True)
#simgr.stashes['bof'] = []
properties = file_properties.file_parser(binary)
format_string = format_string.format_string_detect(binary,function)
local, size_array, size = boflen.stdin_fn(binary)
print(size_array)
if(size_array == []):
    print("\n>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<\n")
    print("NO OVERFLOW DETECTED")
    print("\n>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<\n")
    #format_detect.check_fmt(binary)
    exit(0)
properties = boflen.findmitigation(binary,properties)

#win_addr = boflen.find_win(simgr)

if(properties['nx'] == False):
    shellcode_detect.give_shell(size)
else:
    exploitgen.find_win_rop(size)

