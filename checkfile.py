from pwn import *
import os
from termcolor import cprint

printb_red=lambda x : cprint(x,'red',attrs=['bold'])
print_yellow=lambda x : cprint(x,'yellow')
print_green=lambda x : cprint(x,'green')
print_blue=lambda x : cprint(x,'blue')
print_cyan=lambda x : cprint(x,'cyan')

def file_details(filename):
    p = subprocess.Popen(["file %s"%(filename)], stdout=subprocess.PIPE, shell=True)
    data=p.stdout.read()
    data=data.decode('utf-8')
    file_data=data.split(",")
    printb_red("\n> FILE INFO : \n")
    print("\tELF Name".ljust(15)+" :  "+file_data[0].split(":")[0])
    print("\tELF Type".ljust(15)+" : "+file_data[0].split(":")[1])
    print("\tELF Arch".ljust(15)+" : "+file_data[1])
    print("\tELF SHA1 Hash".ljust(15)+" : "+file_data[5])
    print("\n\tThis binary is",end="")
    print_yellow("%s &%s"%(file_data[3],file_data[7]))
    print_cyan("*"*75)


def elf_checksec(filename):
    p = subprocess.Popen(["/usr/bin/checksec --format=csv --file=%s"%(filename)], stdout=subprocess.PIPE, shell=True)
    data=p.stdout.read()
    data=data.decode('utf-8').split(",")
    printb_red("\n> ELF SECURITY MITIGATIONS : \n")
    print("\tRELRO".ljust(15)+" :  "+data[0])
    print("\tSTACK CANARY".ljust(15)+" :  "+data[1])
    print("\tNX BIT".ljust(15)+" :  "+data[2])
    print("\tPIE".ljust(15)+" :  "+data[3])
    print("\tRPATH".ljust(15)+" :  "+data[4])
    print("\tRUNPATH".ljust(15)+" :  "+data[5]+"\n")
    print_cyan("*"*75)


def sharedobj_details(filename):
    p = subprocess.Popen(["ldd %s"%(filename)], stdout=subprocess.PIPE, shell=True)
    data=p.stdout.read()
    data=data.decode('utf-8').split("\n")
    printb_red("\n> SHARED OBJECT DEPENDENCY : \n")
    for x in data:
        print(x)
    print_cyan("*"*75)


def check_strings(filename):
    p = subprocess.Popen(["rabin2 -z %s"%(filename)], stdout=subprocess.PIPE, shell=True)
    data=p.stdout.read()
    data=data.decode('utf-8').split("\n")
    printb_red("\n> POSSIBLE STRINGS : \n")
    print_blue("\t"+data[1])
    for x in data[2:]:
        print("\t"+x)
    print_cyan("*"*75)

def hexdump_strings(filename):
    p = subprocess.Popen(["readelf -x .rodata %s"%(filename)], stdout=subprocess.PIPE, shell=True)
    data=p.stdout.read()
    data=data.decode('utf-8').split("\n")
    printb_red("\n> RODATA HEXDUMP : \n")
    for x in data[2:]:
        print_green("\t"+x)
    print_cyan("*"*75)