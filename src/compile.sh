#!/usr/bin/sh

if [ -z "$2" ]; then
    echo "Usage: $0 <file name> <output name>"
    exit
fi

echo "Disabling ASLR..."
sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"

echo "Compiling program..."
gcc -g $1 -o $2 -m32 -z execstack -fno-stack-protector -no-pie

