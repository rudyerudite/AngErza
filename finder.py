import claripy
import angr

proj = angr.Project("bug",auto_load_libs=False)

gets = proj.loader.find_symbol('gets')

print(gets)