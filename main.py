#!/usr/bin/python3

from genericpath import exists
from checkfile import check_strings, elf_checksec, file_details, hexdump_strings, sharedobj_details
from table import get_funcs, get_got,get_plt
from defaults import  entrypoint, get_gadgets, headers
from func import asm_and_decompile, asm_func, decompile_func, defined_func, list_userdefined_func
from vulns import check_vuln, got_funcs

from termcolor import cprint
import argparse
import os

print_red=lambda x : cprint(x,'red')
print_yellow=lambda x : cprint(x,'yellow')
print_green=lambda x : cprint(x,'green')
print_cyan=lambda x : cprint(x,'cyan')

def banner():
    print_green(
        '''
         _____ _     ________   ___                  _   
        |  ___| |    |  ___\ \ / / |                | |  
        | |__ | |    | |_   \ V /| |_ _ __ __ _  ___| |_ 
        |  __|| |    |  _|  /   \| __| '__/ _` |/ __| __|
        | |___| |____| |   / /^\ \ |_| | | (_| | (__| |_ 
        \____/\_____/\_|   \/   \/\__|_|  \__,_|\___|\__|

                        @aidenpearce369                                                                  
        '''
    )
    print_cyan("*"*75)

def check_imports():
    try:
        import pwn
        import r2pipe
    except:
        print("> Modules are not properly installed, try installing it properly")
        print("  - pip install pwntools")
        print("  - pip install r2pipe")
        exit()

def check_file(filename):
    if os.path.exists(filename):
            pass
    else:
        print_yellow("Could not find a valid ELF named - %s"%(filename))
        exit()

def basicinfo(filename):
    check_file(filename)
    file_details(filename)
    sharedobj_details(filename)
    elf_checksec(filename)
    check_strings(filename)
    hexdump_strings(filename)

def mapping(filename):
    entrypoint(filename)
    headers(filename)

def gadgetcheck(filename):
    get_gadgets(filename)

def tablecheck(filename):
    get_plt(filename)
    get_got(filename)
    get_funcs(filename)

def functioncheck(filename,time_val):
    funcs=defined_func(filename)
    list_userdefined_func(filename,funcs)
    asm_and_decompile(filename,funcs,time_val)
    got=got_funcs(filename)
    check_vuln(filename,got)

def onlydecompile(filename,time_val):
    funcs=defined_func(filename)
    decompile_func(filename,funcs,time_val)

def onlyasm(filename,time_val):
    funcs=defined_func(filename)
    asm_func(filename,funcs,time_val)

if __name__ == "__main__":
    banner()
    check_imports()
    parser=argparse.ArgumentParser()  
    parser.add_argument("-f","--file",required=True,help="Path of the ELF")
    parser.add_argument("-a","--all",help="Extract all info",action="store_true")
    parser.add_argument("-i","--info",help="Displays basic info",action="store_true")
    parser.add_argument("-g","--gadgets",help="Displays gadgets",action="store_true")
    parser.add_argument("--user-func",help="Displays the details of user defined functions",action="store_true")
    parser.add_argument("--asm-only",help="Displays the ASM of ELF",action="store_true")
    parser.add_argument("--decompiled-only",help="Displays the decompiled C code of ELF",action="store_true")
    parser.add_argument("-t","--tables",help="Displays PLT, GOT & Function table",action="store_true")
    args=parser.parse_args()
    check_file(args.file)
    if(args.all):
        basicinfo(args.file)
        mapping(args.file)
        gadgetcheck(args.file)
        tablecheck(args.file)
        functioncheck(args.file,5)
    if((args.all)==False and (args.info)==True):
        basicinfo(args.file)
    if((args.all)==False and (args.gadgets)==True):
        gadgetcheck(args.file)
    if((args.all)==False and (args.tables)==True):
        tablecheck(args.file)
    if((args.all)==False and (args.user_func)==True):
        functioncheck(args.file,5)
    if((args.all)==False and (args.decompiled_only)==True):
        onlydecompile(args.file,5)
    if((args.all)==False and (args.asm_only)==True):
        onlyasm(args.file,5)
    