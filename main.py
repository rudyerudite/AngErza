from pwn import *
import angr
from lib import boflen
from lib import file_properties
from lib import exploitgen

binary = sys.argv[1]
proj = angr.Project(binary,auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFile)
simgr = proj.factory.simulation_manager(state,save_unconstrained=True)
#simgr.stashes['bof'] = []
properties = file_properties.file_parser(binary)
local, size_array, size = boflen.stdin_fn(binary)
boflen.findmitigation(binary,properties)
#win_addr = boflen.find_win(simgr)
exploitgen.find_win_rop(size)
