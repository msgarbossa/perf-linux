#!/usr/bin/python

import os
import sys
from subprocess import call
import getopt

# set defaults
opt_verify = False

# Parse CLI input
try:
    opts, args = getopt.getopt(sys.argv[1:], "v")
except getopt.GetoptError:
    print("use -v to only perform verification or run without options to verify and install packages")
for opt, arg in opts:
    if opt == '-v':
        opt_verify = True


pkgs = []

if not os.path.exists("/bin/mpstat"):
    print("Install systat.")
    pkgs.append('sysstat')

if not os.path.exists("/sbin/iotop"):
    print("Install iotop.")
    pkgs.append('iotop')

if not os.path.exists("/sbin/iotop"):
    print("Install iotop.")
    pkgs.append('iotop')

if not os.path.exists("/usr/sbin/tcpdump"):
    print("Install tcpdump.")
    pkgs.append('tcpdump')

count = len(pkgs)
if count > 0:
    if opt_verify:
        print("Run ./setup.py (without -v option to verify) to fix or install packages manually")
        sys.exit(1)
    else:
        if os.path.exists('/bin/yum'):
            cmd = 'yum install -y ' + ' '.join(pkgs)
            print(cmd)
            call(cmd, shell=True)
        if os.path.exists('/usr/bin/apt'):
            cmd = 'apt install -y ' + ' '.join(pkgs)
            print(cmd)
            call(cmd, shell=True)
else:
    sys.exit(0)
