import subprocess
from pwn import *

linking = ""
arch = ""

filename = "/home/b3y0nd3r/final-year-project/test_cases/bug1"
def check_elf(filename):
    f = open(filename,"rb")
    header = f.read(4)
    if(header == b'\x7fELF'):
        print("ELF file detected.")
    else:
        exit(0)

def check_linking(filename):
    output = str(subprocess.check_output("file " + filename, shell=True))
    output = output.split(",")
    output = output[3].strip()
    if(output == "dynamically linked"):
        linking = "dyn"
        libc_path = input("Please enter the libc file path > ")
    elif(output == "statically linked"):
        linking = "static"
    print(linking)
    return linking

def check_arch(filename):
    output = str(subprocess.check_output("file " + filename, shell=True))
    output = output.split(",")
    output = output[0].split(":")
    output = output[1].strip()
    if(output == "ELF 64-bit LSB executable"):
        arch = "64"
    elif(output == "ELF 64-bit LSB executable"):
        arch = "32"
    print(arch)
    return arch

check_elf(filename)
check_linking(filename)
check_arch(filename)
