#!/usr/bin/env python3

import os
import signal
import subprocess
import sys
from time import time, sleep, localtime, strftime
import getopt
import re

# from subprocess import call

def usage(exit_code=0):
    """Display help message if -h option used or invalid syntax."""
    print(os.path.basename(__file__) + ' [-w <output_file>] [-t <timeout_sec>]')
    print("")
    sys.exit(exit_code)

# default arguments
base_dir = os.path.dirname(os.path.abspath(__file__))
datetime = strftime("%Y-%m-%d_%H%M%S", localtime())
arg_dict = {}
arg_dict['output_file'] = './tcpdump.{0}.pcap'.format(datetime)
arg_dict['timeout_sec'] = "10"

try:
    opts, args = getopt.getopt(sys.argv[1:], "ht:w:")
except getopt.GetoptError:
    usage(1)
for opt, arg in opts:
    if opt == '-h':
        usage()
    elif opt in ("-t"):
        arg_dict['timeout_sec'] = arg
    elif opt in ("-w"):
        arg_dict['output_file'] = arg

# Find network interface with default route
interface = False
pid = subprocess.Popen('netstat -rn', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
netstat_stdout = pid.communicate()[0]
for line in netstat_stdout.splitlines():
    line = line.decode('utf-8')
    line.strip()
    if line.startswith('0.0.0.0'):
        interface = line.split()[-1]
        break

if not interface:
    print("ERROR: Could not determine interface with default route from netstat -rn")
    sys.exit(1)

cmd = '/usr/sbin/tcpdump -i {0} -nn -w {1}'.format(interface, arg_dict['output_file'])

pid = os.fork()
if pid > 0:
    # print('parent pid is {0}'.format(os.getpid()))
    pid_tcpdump = pid
else:
    # child
    os.setpgrp() # Set process group so the child processes are cleaned up (avoids long running tcpdump in the background)
    print('forked child pid {0} to run tcpdump'.format(os.getpid()))
    subprocess.call(cmd, shell=True)
    os._exit(0)

print('waiting {0} seconds for tcpdump to finish'.format(arg_dict['timeout_sec']))
sleep(int(arg_dict['timeout_sec']))
os.kill(-pid_tcpdump, signal.SIGHUP)  # negative sign in front of pid to cleanup process group
print('tcpdump pid {0} finished'.format(pid_tcpdump))
