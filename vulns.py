from pwn import *
from termcolor import cprint

print_red=lambda x : cprint(x,'red')
printb_red=lambda x : cprint(x,'red',attrs=['bold'])
print_yellow=lambda x : cprint(x,'yellow')
print_green=lambda x : cprint(x,'green')
printb_green=lambda x : cprint(x,'green',attrs=['bold'])
print_cyan=lambda x : cprint(x,'cyan')

frmstr=['fprintf','fscanf','printf','scanf','sprintf','sscanf']
cmdexec=['system','execl','execle','execlp','execv','execve','execvp','popen']
bof=['calloc','malloc','realloc','fscanf','gets','scanf','sprintf','sscanf','strcat','strcpy','strncat','strncmp','strncpy','memchr','memcmp','memcpy','memmove','memset','scanf','gets','fwscan','sscanf']

def got_funcs(filename):
    e = ELF(filename,checksec=False)
    data=e.got
    funcs=[]
    for x in data:
        funcs.append(x)
    return funcs
    

def check_vuln(filename,funcs):
    printb_red("\n> VULNERABLE FUNCTIONS : \n")
    for x in funcs:
        if x in frmstr:
            data=get_vuln_asm_inst(filename,x)
            if(len(data)>5):
                print("\tPossible vulnerability locations - ",end="")
                printb_green("Format String\n")
                print_yellow(data)
        if x in bof:
            data=get_vuln_asm_inst(filename,x)
            if(len(data)>5):
                print("\tPossible vulnerability locations - ",end="")
                printb_green("Buffer Overflow\n")
                print_yellow(data)
        if x in cmdexec:
            data=get_vuln_asm_inst(filename,x)
            if(len(data)>5):
                print("\tPossible vulnerability locations - ",end="")
                printb_green("Command Execution\n")
                print_yellow(data)
    print_cyan("\n"+"*"*75)

def get_vuln_asm_inst(filename,fname):
    p = subprocess.Popen(["cat /tmp/elfxtract_inst | grep %s"%(fname)], stdout=subprocess.PIPE, shell=True)
    data=p.stdout.read()
    data=data.decode('utf-8').replace("│ "," ")
    return(data)

