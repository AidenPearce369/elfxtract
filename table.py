from pwn import *
from termcolor import cprint

printb_red=lambda x : cprint(x,'red',attrs=['bold'])
print_cyan=lambda x : cprint(x,'cyan')


def get_got(filename):
    e = ELF(filename,checksec=False)
    data=e.got
    printb_red("\n> GOT TABLE : \n")
    for x in data:
        print("\t"+x.ljust(35)+" : "+str(hex(data[x])).rjust(10))
    print_cyan("\n"+"*"*75)


def get_plt(filename):
    e = ELF(filename,checksec=False)
    data=e.plt
    printb_red("\n> PLT TABLE : \n")
    for x in data:
        print("\t"+x.ljust(35)+" : "+str(hex(data[x])).rjust(10))
    print_cyan("\n"+"*"*75)


def get_funcs(filename):
    e = ELF(filename,checksec=False)
    data=e.functions
    printb_red("\n> FUNCTION TABLE : \n")
    for x in data:
        print("\t"+x.ljust(35)+" : "+str(data[x])[9:-1].split(",")[1][9:].rjust(10))
    print_cyan("\n"+"*"*75)



    