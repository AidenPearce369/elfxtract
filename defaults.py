from pwn import *
from termcolor import cprint

printb_red=lambda x : cprint(x,'red',attrs=['bold'])
print_yellow=lambda x : cprint(x,'yellow')
print_cyan=lambda x : cprint(x,'cyan')

def entrypoint(filename):
    e = ELF(filename,checksec=False)
    data=e.functions
    printb_red("\n> ELF ENTRY POINT : \n")
    print("\tThe entry point of the ELF is at ",end="")
    print_yellow(str(hex(e.entrypoint))+"\n")
    print_cyan("*"*75)

def headers(filename):
    p = subprocess.Popen(["readelf -l %s | sed -n '/Program Headers:/,/Section to Segment mapping:/p'"%(filename)], stdout=subprocess.PIPE, shell=True)
    data=p.stdout.read()
    data=data.decode('utf-8')
    printb_red("\n> HEADER MEMORY MAP : \n")
    print(data[17:-30])
    print_cyan("*"*75)

def get_gadgets(filename):
    e = ELF(filename,checksec=False)
    r=ROP(e)
    g=r.gadgets
    g=g.values()
    printb_red("\n> ROP GADGETS : \n")
    for x in g:
        y=str(x).replace("Gadget","")
        y_tuple=eval(y)
        print_yellow("\t"+str(hex(y_tuple[0])).ljust(10)+" : "+";".join(list(y_tuple[1])))
    print_cyan("\n"+"*"*75)