from one_gadget import generate_one_gadget

path_to_libc = '/lib/x86_64-linux-gnu/libc.so.6'
#doesn't give all the gadgets
for offset in generate_one_gadget(path_to_libc):
    print(hex(offset))