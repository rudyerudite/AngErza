from pwn import *
import angr
from lib import file_properties
from lib import boflen
from lib import exploitgen
from lib import shellcode_detect
from lib import format_string

binary = sys.argv[1]

#loading the project for analysis
proj = angr.Project(binary,auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFile)
simgr = proj.factory.simulation_manager(state,save_unconstrained=True)

#finding file properties
file_properties = file_properties.file_parser(binary)
print(file_properties)
properties = boflen.findmitigation(binary,file_properties)
#finding buffer overflow property
local, size_array, size = boflen.stdin_fn(binary)

if(size_array == [] and [properties['nx']] != [False]):
    print("\n>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<\n")
    print("NO OVERFLOW DETECTED")
    print("\n>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<\n")
    print("\n CHECKING FOR FORMAT STRING BUG...\n")
    function = boflen.findfunctions(binary)
    format_string = format_string.format_string_detect(binary,function)

    if(format_string == True):
        print("\n FORMAT STRING BUG DETECTED\n")
    else:
        print("\n...FORMAT STRING BUG NOT DETECTED")
else:
    s = 0
    k = ""
    if([properties['nx']] == [False]):
        print("\n CHECKING FOR SHELLCODE PAYLOAD...\n")
        s = shellcode_detect.give_shell(size)
    if(s == 0 and not(size_array == [])):
        print("\n CHECKING FOR ROPCHAIN...\n")
        k = exploitgen.find_win_rop(size)
    if( s==0 and k == "" and not(size_array == [])):
        print("\n CHECKING FOR SYSCALL ROPCHAIN ...\n")
        exploitgen.find_rop(size)

