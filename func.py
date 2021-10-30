from pwn import *
from pwnlib.term.term import flush
import r2pipe
import time
from termcolor import cprint

printb_red=lambda x : cprint(x,'red',attrs=['bold'])
print_yellow=lambda x : cprint(x,'yellow')
printb_green=lambda x : cprint(x,'green',attrs=['bold'])
print_cyan=lambda x : cprint(x,'cyan')

def defined_func(filename):
    e = ELF("%s"%(filename),checksec=False)
    data=e.functions
    functions=[]
    userdefined_func=[]
    for x in data:
        functions.append(x)
    inbuilt=['__libc_csu_fini','__libc_csu_init','_start','__stack_chk_fail_local','__x86.get_pc_thunk.bx']
    for x in functions:
        if x not in inbuilt:
            userdefined_func.append(x)
    return userdefined_func

def list_userdefined_func(filename,funcs):
    e = ELF("%s"%(filename),checksec=False)
    printb_red("\n> POSSIBLE USER DEFINED FUNCTIONS : \n")
    if len(funcs)==0:
        print_yellow("Could not find possible user defined functions")
    else:
        for x in funcs:
            print_yellow("\t"+x.ljust(20)+" : "+str(hex(e.symbols[x])).rjust(10))
    print_cyan("\n"+"*"*75)


def get_decompile(filename,x):
    r = r2pipe.open('%s'%(filename),flags=['-2'])
    r.cmd("aaa")
    r.cmd("s sym.%s"%(x))
    printb_green("\n[*] DECOMPILED CODE - %s : \n"%(x))
    data=r.cmd('pdg')
    print(data)

def get_asm(filename,f,x):
    r = r2pipe.open('%s'%(filename),flags=['-2'])
    r.cmd("aaa")
    r.cmd("s sym.%s"%(x))
    printb_green("\n[*] ASM - %s : \n"%(x))
    data=r.cmd('pdf')
    f.write(data)
    print(data)
    

def decompile_func(filename,funcs,time_val):
    printb_red("\n> DECOMPILED CODE : \n")
    if len(funcs)==0:
        print_yellow("Could not find possible user defined functions")
    else:
        for x in funcs:
            get_decompile(filename,x)
    print_cyan("\n"+"*"*75)

def asm_func(filename,funcs,time_val):
    printb_red("\n> ASM CODE : \n")
    if len(funcs)==0:
        print_yellow("Could not find possible user defined functions")
    else:
        f=open("/tmp/elfxtract_inst","w")
        for x in funcs:
            get_asm(filename,f,x)
        f.close()
    print_cyan("\n"+"*"*75)

def asm_and_decompile(filename,funcs,time_val):
    printb_red("\n> ASSEMBLY AND DECOMPILED CODE : \n")
    if len(funcs)==0:
        print_yellow("Could not find possible user defined functions")
    else:
        f=open("/tmp/elfxtract_inst","w")
        for x in funcs:
            get_asm(filename,f,x)
            get_decompile(filename,x)
        f.close()
    print_cyan("\n"+"*"*75)
