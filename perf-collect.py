#!/usr/bin/env python3

import os
from time import time, localtime, strftime
from subprocess import call

# set default collection options
duration = 60
duration_str = str(duration)


#############################################
# Deal with directory structure and symlink #
#############################################

base_dir = os.path.dirname(os.path.abspath(__file__))
plugin_dir = os.path.join(base_dir, 'plugins')
data_dir = os.path.join(base_dir, 'data')
datetime = strftime("%Y-%m-%d_%H%M%S", localtime())
date_dir = os.path.join(data_dir, datetime)
cmd_out_dir = os.path.join(date_dir, 'cmds_out')
report_out_dir = os.path.join(date_dir, 'reports_out')

if not os.path.exists(cmd_out_dir):
    os.makedirs(cmd_out_dir)

if not os.path.exists(data_dir):
    os.makedirs(data_dir)

os.chdir(data_dir)
if os.path.exists("current"):
    os.remove("current")
ln_src = os.path.join(data_dir, "current")
os.symlink(datetime, ln_src)

if not os.path.exists(report_out_dir):
    os.makedirs(report_out_dir)

# change to directory for the current data collection
os.chdir(cmd_out_dir)
# set environment variable for data collection
os.environ['CMD_OUT_DIR'] = cmd_out_dir


#############################
# Collect starting commands #
#############################

start_time = time()

call('ps auxf >psf.out', shell=True)
call('ps aux >ps.out', shell=True)
#call('ps -www -eo \"pmem pcpu time vsz rss user pid args\" >ps_custom.out', shell=True)
call('free -m >free.out', shell=True)
call('cat /proc/meminfo >meminfo.out', shell=True)
call('netstat -an >netstat_an.out', shell=True)
call('netstat -in >netstat_in_start.out', shell=True)


#######################################
# Collect commands in parallel (fork) #
#######################################

children = []

print("forking tcpdump")
cmd = '{0}/tcpdump-collect.py -w {1} -t 10'.format(plugin_dir, os.path.join(cmd_out_dir, 'tcpdump.pcap'))
pid = os.fork()
if pid > 0:
    # parent
    children.append(pid)
else:
    # child
    call(cmd, shell=True)
    os._exit(0)

print("forking mpstat")
cmd = 'mpstat 1 ' + duration_str + ' -P ALL >mpstat.out'
pid = os.fork()
if pid > 0:
    # parent
    children.append(pid)
else:
    # child
    call(cmd, shell=True)
    os._exit(0)

print("forking vmstat")
cmd = 'vmstat 1 ' + duration_str + ' >vmstat.out'
pid = os.fork()
if pid > 0:
    # parent
    children.append(pid)
else:
    # child
    call(cmd, shell=True)
    os._exit(0)

print("forking iostat")
cmd = 'iostat -t -z -x 1 ' + duration_str + ' >iostat.out'
pid = os.fork()
if pid > 0:
    # parent
    children.append(pid)
else:
    # child
    call(cmd, shell=True)
    os._exit(0)

print("forking sar")
# cmd = 'sar -o sarA.bin -A 1 ' + duration_str + ' -p >sarA.out'
for sadc in ['/usr/lib/sysstat/sadc', '/usr/lib64/sa/sadc']:
    if os.path.exists(sadc):
        break

cmd = sadc + ' -S ALL 1 ' + duration_str + ' sarA.bin'
pid = os.fork()
if pid > 0:
    # parent
    children.append(pid)
else:
    # child
    call(cmd, shell=True)
    os._exit(0)

print("forking iotop")
interval = 5
interval_str = str(interval)
samples_str = str(int(duration / interval))
cmd = 'iotop -o -n ' + samples_str + ' -d ' + interval_str + ' -b >iotop.out'
pid = os.fork()
if pid > 0:
    # parent
    children.append(pid)
else:
    # child
    call(cmd, shell=True)
    os._exit(0)

print("forking top")
interval = 5
interval_str = str(interval)
samples_str = str(int(duration / interval))
cmd = 'top -n ' + samples_str + ' -d ' + interval_str + ' -b >top.out'
pid = os.fork()
if pid > 0:
    # parent
    children.append(pid)
else:
    # child
    call(cmd, shell=True)
    os._exit(0)


#print("forking point-in-time commands"
#interval = 2
#samples = int(duration / interval)
#cmds = []
#cmds.append 'pidstat >> pidstat.out'
#pid = os.fork()
#if pid > 0:
#    # parent
#    children.append(pid)
#else:
#    # child
#    for cmd in cmds:
#        call(cmd , shell=True)
#        sleep interval_dbl
#    os._exit(0)

print('waiting for forked processes to finish: ' + duration_str + ' seconds')
for child in children:
    os.waitpid(child, 0)

#date >> /tmp/top.out; top -n 1 -b >> /tmp/top.out
#date >> /tmp/psf.out; ps auxf >> /tmp/psf.out
#date >> /tmp/ps.out  ; ps aux >> /tmp/ps.out
#date >> /tmp/pidstat.out ; pidstat >> /tmp/pidstat.out &


###########################
# Collect ending commands #
###########################

call('netstat -in >netstat_in_end.out', shell=True)
call('ifconfig -a >ifconfig_a.out', shell=True)
call('uname >uname.out', shell=True)
call('cat /proc/cpuinfo >cpuinfo.out', shell=True)
call('mount >mount.out', shell=True)
call('df -Pk >df_Pk.out', shell=True)
call('df -i >df_i.out', shell=True)

##########################
# Post-process any files #
##########################

# for perf-analyze.py
call('sadf -U -d sarA.bin -- -A  >sarA.data', shell=True)

# for ksar
call('LC_ALL=C sar -A -f sarA.bin >> sarA.ksar; gzip sarA.ksar', shell=True)

elapsed = time() - start_time
print('Elapsed time: {0}.'.format(elapsed))
