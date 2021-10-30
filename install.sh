#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "Running this script as : $USER" 
   echo "********************************************************************************"
fi
sudo apt install python3 python3-pip checksec binutils git
echo "********************************************************************************"
if [ -d "$HOME/radare2/" ] 
then
    echo "Directory $HOME/radare2/ exists." 
    exit 1
else
    echo "Directory $HOME/radare2/ does not exists."
    cd $HOME
    git clone https://github.com/radareorg/radare2
    $HOME/radare2/sys/install.sh
    r2pm update
    r2pm -ci r2ghidra
fi
echo "SUCCESS !!"
