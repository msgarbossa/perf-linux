#!/usr/bin/env python3

# from time import time, strftime, localtime
from subprocess import STDOUT, call, Popen, PIPE
import os
import sys
import re
import getopt
import csv
import decimal
decimal.getcontext().prec = 4

# modules in current directory
from tabulate import tabulate
from mod_stats import *

# set default collection options
duration = 60
duration_str = str(duration)

#############################################
# Deal with directory structure and symlink #
#############################################

base_dir = os.path.dirname(os.path.abspath(__file__))
plugin_dir = os.path.join(base_dir, 'plugins')
data_dir = os.path.join(base_dir, 'data')
date_dir = os.path.join(data_dir, 'current')
cmd_out_dir = os.path.join(date_dir, 'cmds_out')
report_out_dir = os.path.join(date_dir, 'reports_out')

if not os.path.exists(report_out_dir):
    os.makedirs(report_out_dir)

re_start_slash = re.compile('^\/')

try:
    opts, args = getopt.getopt(sys.argv[1:], "hd:o:", ["cmd_out_dir=", "output_dir="])
    #opts, args = getopt.getopt(sys.argv[1:],"hd:o:")
except getopt.GetoptError:
    print('perf-analyze.py -d <cmd_out_dir> -o <output_dir>')
    sys.exit(2)
for opt, arg in opts:
    if opt == '-h':
        print('perf-analyze.py -d <cmd_out_dir> -o <output_dir>')
        sys.exit()
    elif opt in ("-d", "--cmd_out_dir"):
        if not re_start_slash.match(arg):
            arg = os.path.join(base_dir, arg)
        cmd_out_dir = arg
        date_dir = arg
    elif opt in ("-o", "--output_dir"):
        date_dir = arg

# if not os.path.exists(cmd_out_dir):
#     print('Cannot find ./data/current symlink to date-stamped directory')
#     os._exit(1)

# change to directory for the current sample collection
os.chdir(date_dir)

# generic read a file line by line
#if os.path.exists(file):
#    # read file
#    with open(file) as f:
#        for line in f:
#            print(line.rstrip())


########################################
# Read any relevant host configuration #
########################################

# get ifconfig -a mapping of adapters

# get number of VCPUs


##################
# Process vmstat #
##################

file = os.path.join(cmd_out_dir, 'vmstat.out')

# ref: http://www.eurion.net/python-snippets/snippet/vmstat%20Reader.html

# Create a map from minor to major header as the minor headers are easy to
# associate to columns, which is not the case for major headers.
minor2major = {
    'r': 'procs',
    'b': 'procs',
    'swpd': 'memory',
    'free': 'memory',
    'buff': 'memory',
    'cache': 'memory',
    'inact': 'memory',  # to support the vmstat -a option if required
    'active': 'memory', # to support the vmstat -a option if required
    'si': 'swap',
    'so': 'swap',
    'bi': 'io',
    'bo': 'io',
    'in': 'system',
    'cs': 'system',
    'us': 'cpu',
    'sy': 'cpu',
    'id': 'cpu',
    'wa': 'cpu',
    'st': 'cpu'
}
minors = []
flag_found_minor = False

# Initialise the vmstat_data map by creating an empty sub-map against each
# unique major header
vmstat_data = dict([(h, {}) for h in set(minor2major.values())])

# compile regex objects
re_dates = re.compile(r"\d+:\d+:\d+")

# Create the reader and specify the delimier to be a space; also set the
# skipinitialspace flag to true to ensure that several spaces are seen as a
# single delimiter and that initial spaces in a line are ignored
reader = csv.reader(open(file), delimiter=' ', skipinitialspace=True)
for row in reader:
    if re_dates.match(row[3]):
        """
        skip lines w/ dates (redhat likes these)
        """
    elif row[0] == "procs":
        """
        Ignore the first line as it contains major headers.
        """
    elif row[0] == "r":
        if not flag_found_minor:
            """
            If we are on the first line, create the headers list from the first row.
            We also keep a copy of the minor headers, in the order that they appear
            in the file to ensure that we can map the values to the correct entry
            in the vmstat_data map.
            """
            minors = row
            for h in row:
                vmstat_data[minor2major[h]][h] = []
            flag_found_minor = True
    elif row[0] != minors[0] and row[0] != minor2major[minors[0]]:
        """
        If the -n option was not specified when running the vmstat command,
        major and minor headers are repeated so we need to ensure that we
        ignore such lines and only deal with lines that contain actual data.
        For each value in the row, we append it to the respective entry in
        the vmstat_data dictionary. In addition, we transform the value to an int
        before appending it as we know that the vmstat_data of the log should only
        have integer values.
        """
        for i, v in enumerate(row):
            vmstat_data[minor2major[minors[i]]][minors[i]].append(int(v))


# Initialize list for storing rows for the report and add header row
stats = []
s_row = ['metric', 'avg', 'sd', 'min', 'max', 'description']
stats.append(s_row)

# usr
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['cpu']['us'], 1)
s_row = ['usr', s_avg, s_sd, s_min, s_max, '% CPU for user processes']
stats.append(s_row)

# sys
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['cpu']['sy'], 1)
s_row = ['sys', s_avg, s_sd, s_min, s_max, '% CPU for system processes']
stats.append(s_row)

# wait
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['cpu']['wa'], 1)
s_row = ['wait', s_avg, s_sd, s_min, s_max, '% CPU wait']
stats.append(s_row)

# run queue
# r: The number of runnable processes (running or waiting for run time).
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['procs']['r'], 1)
#avg = fmtRed(avg)
s_row = ['r', s_avg, s_sd, s_min, s_max, 'run queue']
stats.append(s_row)

# blocked queue
# b: The number of processes in uninterruptible sleep.
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['procs']['b'], 1)
s_row = ['b', s_avg, s_sd, s_min, s_max, 'processes in uninterruptible sleep']
stats.append(s_row)

# context switching
# cs: The number of context switches per second.
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['system']['cs'], 0)
#avg = fmtRed(avg)
s_row = ['cs', s_avg, s_sd, s_min, s_max, 'CPU context switch/s']
stats.append(s_row)

# interrupts
# in: The number of interrupts per second, including the clock.
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['system']['in'], 0)
s_row = ['in', s_avg, s_sd, s_min, s_max, 'interrupts/s']
stats.append(s_row)

# swap in
# si: Amount of memory swapped in from disk (/s).
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['swap']['si'], 0)
s_row = ['si', s_avg, s_sd, s_min, s_max, 'swap in from disk /s']
stats.append(s_row)

# swap out
# so: Amount of memory swapped to disk (/s).
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['swap']['so'], 0)
s_row = ['so', s_avg, s_sd, s_min, s_max, 'swap out to disk /s']
stats.append(s_row)

# blocks in
# bi: Blocks received from a block device (blocks/s).
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['io']['bi'], 0)
s_row = ['bi', s_avg, s_sd, s_min, s_max, 'block read /s']
stats.append(s_row)

# blocks out
# bo: Blocks sent to a block device (blocks/s).
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(vmstat_data['io']['bo'], 0)
s_row = ['bo', s_avg, s_sd, s_min, s_max, 'block write /s']
stats.append(s_row)



##################
# Process sar -A #
##################
# todo - handle if sarA.data does not exist
# look for binary and convert or find sarA.out and convert

# Create a map of header fields to key fields per sample
header2key = {
    'pswpin/s': '',
    'pswpout/s': '',
    'pgpgin/s': '',
    'pgpgout/s': '',
    'fault/s': '',
    'majflt/s': '',
    'pgfree/s': '',
    'pgscank/s': '',
    'pgscand/s': '',
    'pgsteal/s': '',
    '%vmeff': '',
    'file-nr': '',
    'inode-nr': '',
    'proc/s': '',
    'plist-sz': '',
    'tps': '',
    'rtps': '',
    'wtps': '',
    'bread/s': '',
    'bwrtn/s': '',
    'rxpck/s': 'IFACE',
    'txpck/s': 'IFACE',
    'rxkB/s': 'IFACE',
    'txkB/s': 'IFACE',
    'rxmcst/s': 'IFACE',
    'rxerr/s': 'IFACE',
    'txerr/s': 'IFACE',
    'rxdrop/s': 'IFACE',
    'txdrop/s': 'IFACE'
}

# Initialise the sar_data map by creating an empty sub-map against each
# unique major header
sar_data = {}
sar_data['IFACE'] = {}
for h in set(header2key.keys()):
    if header2key[h]:
        # don't need to intialize entries w/ multiple key values because
        # they'll be initalized later
        continue
    else:
        # initialize entries that just need data collected
        sar_data[h] = []


re_header = re.compile('^#')

file = os.path.join(cmd_out_dir, 'sarA.data')
flag_read_data = False
key_idx = -1
key_name = ''

reader = csv.reader(open(file), delimiter=';', skipinitialspace=True)
for row in reader:
    if re_header.match(row[0]):
        flag_read_data = False
        key_idx = -1
        key_name = ''
        for i, h in enumerate(row):
            if h in header2key:
                flag_read_data = True
                header = row
                if header2key[h]:
                    key_name = header2key[h]
        if key_name:
            for i, h in enumerate(row):
                if h == key_name:
                    key_idx = i
    elif flag_read_data:
        if key_idx < 0:
            for i, v in enumerate(row):
                if header[i] in header2key:
                    sar_data[header[i]].append(decimal.Decimal(v))
        if key_idx >= 0:
            key_val = row[key_idx]
            for i, v in enumerate(row):
                if header[i] in header2key:
                    if key_val not in sar_data[key_name]:
                        sar_data[key_name][key_val] = {}
                    if header[i] not in sar_data[key_name][key_val]:
                        sar_data[key_name][key_val][header[i]] = []
                    sar_data[key_name][key_val][header[i]].append(decimal.Decimal(v))


# pswpin/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['pswpin/s'], 0)
s_row = ['pswpin/s', s_avg, s_sd, s_min, s_max, 'swap pages in /s']
stats.append(s_row)

# pswpout/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['pswpout/s'], 0)
s_row = ['pswpout/s', s_avg, s_sd, s_min, s_max, 'swap pages out /s']
stats.append(s_row)

# pgpgin/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['pgpgin/s'], 0)
s_row = ['pgpgin/s', s_avg, s_sd, s_min, s_max, 'KB paged in from disk /s']
stats.append(s_row)

# pgpgout/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['pgpgout/s'], 0)
s_row = ['pgpgout/s', s_avg, s_sd, s_min, s_max, 'KB paged out to disk /s']
stats.append(s_row)

# faults/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['fault/s'], 0)
s_row = ['fault/s', s_avg, s_sd, s_min, s_max, 'major+minor page faults /s']
stats.append(s_row)

# majflt/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['majflt/s'], 0)
s_row = ['majflt/s', s_avg, s_sd, s_min, s_max, 'page faults that required loading from disk /s']
stats.append(s_row)

# pgfree/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['pgfree/s'], 0)
s_row = ['pgfree/s', s_avg, s_sd, s_min, s_max, 'pages placed on free list /s']
stats.append(s_row)

# pgscank/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['pgscank/s'], 0)
s_row = ['pgscank/s', s_avg, s_sd, s_min, s_max, 'pages scanned by kswapd /s']
stats.append(s_row)

# pgscand/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['pgscand/s'], 0)
s_row = ['pgscand/s', s_avg, s_sd, s_min, s_max, 'pages scanned directly /s']
stats.append(s_row)

# pgsteal/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['pgsteal/s'], 0)
s_row = ['pgsteal/s', s_avg, s_sd, s_min, s_max, 'pages reclaimed from cache to satisfy demand']
stats.append(s_row)

# %vmeff
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['%vmeff'], 1)
s_row = ['%vmeff', s_avg, s_sd, s_min, s_max, 'pgsteal/pgscan=virtual memory efficiency']
stats.append(s_row)

# file-nr
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['file-nr'], 0)
s_row = ['file-nr', s_avg, s_sd, s_min, s_max, 'number of file handles']
stats.append(s_row)

# inode-nr
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['inode-nr'], 0)
s_row = ['inode-nr', s_avg, s_sd, s_min, s_max, 'number of inode handlers']
stats.append(s_row)

# proc/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['proc/s'], 1)
s_row = ['proc/s', s_avg, s_sd, s_min, s_max, 'tasks created /s']
stats.append(s_row)

# plist-sz
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['plist-sz'], 0)
s_row = ['plist-sz', s_avg, s_sd, s_min, s_max, 'number of tasks in task list']
stats.append(s_row)

# tps
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['tps'], 0)
s_row = ['tps', s_avg, s_sd, s_min, s_max, 'transfers per second to physical devices (IOPS)']
stats.append(s_row)

# rtps
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['rtps'], 0)
s_row = ['rtps', s_avg, s_sd, s_min, s_max, 'read IOPS']
stats.append(s_row)

# wtps
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['wtps'], 0)
s_row = ['wtps', s_avg, s_sd, s_min, s_max, 'write IOPS']
stats.append(s_row)

# bread/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['bread/s'], 0)
s_row = ['bread/s', s_avg, s_sd, s_min, s_max, 'block reads (512B) /s']
stats.append(s_row)

# bwrtn/s
(s_avg, s_sd, s_min, s_max) = calc_avg_sd(sar_data['bwrtn/s'], 0)
s_row = ['bwrtn/s', s_avg, s_sd, s_min, s_max, 'block writes (512B) /s']
stats.append(s_row)


######################
# Print Basic Report #
######################

# Print the contents of the report file
reportfile = os.path.join(report_out_dir, 'report.out')
with open(reportfile, 'w') as fout:
    # ref: https://pypi.python.org/pypi/tabulate
    fout.write(tabulate(stats, headers="firstrow"))
    fout.write('\n\n\n')


################################
# Print Network Adapter Report #
################################

# todo - need an external data file to store configuration, including
#   order of fields to report on
#   thresholds for each field
#   descriptions of each filed

# Initialize list for storing rows for the report and add header row
stats = []
row = ['adapter', 'metric', 'avg', 'sd', 'min', 'max']
stats.append(row)

re_non_zero = re.compile('drop|err')

for i, x in enumerate(sar_data['IFACE']):
    for j, y in enumerate(sar_data['IFACE'][x]):
        (avg, sd, min, max) = calc_avg_sd(sar_data['IFACE'][x][y], 1)

        ######################
        # process thresholds #
        ######################
        if re_non_zero.search(y):
            if decimal.Decimal(avg) > 0:
                avg = fmtRed(avg)

        # add row to stats table
        row = [x, y, avg, sd, min, max]
        stats.append(row)

    # Need to figure out why this is looping more than the number of adapters (i/x)
    row = ['', '', '', '', '', '']
    stats.append(row)


with open(reportfile, 'a') as fout:
    fout.write(tabulate(stats, headers="firstrow"))
    fout.write('\n\n\n')

#####################################
# Analyze netstat and create report #
#####################################

# Run netstat_analyser.py to write IP lookup cache to file and write report file with lookups
outfile = os.path.join(report_out_dir, 'netstat_an_dns.report')
cmd = os.path.join(plugin_dir, 'netstat_analyser.py')
cmd = cmd + " -n -r " + cmd_out_dir + " -w " + cmd_out_dir + " > " + outfile
call(cmd , shell=True)

# Create report file from netstat output file
outfile = os.path.join(report_out_dir, 'netstat_an.report')
cmd = os.path.join(plugin_dir, 'netstat_analyser.py')
cmd = cmd + " -r " + cmd_out_dir + " > " + outfile
call(cmd , shell=True)

with open(reportfile, 'a') as fout:
    fout.write("************************\n")
    fout.write("** netstat -an report **\n")
    fout.write("************************\n")
    with open(outfile, 'r') as fin:
        fout.write(fin.read())
    fout.write('\n\n\n')

#####################################
# Analyze tcpdump and create report #
#####################################

# Create report file from netstat output file
outfile = os.path.join(report_out_dir, 'tcpdump.report')
cmd = os.path.join(plugin_dir, 'tcpdump-analyze.py')
pcap_file = os.path.join(cmd_out_dir, 'tcpdump.pcap')
cmd = cmd + " -r " + pcap_file + " > " + outfile
call(cmd , shell=True)

# combine tcpdump report "outfile" into aggregated reportfile (report.txt)
with open(reportfile, 'a') as fout:
    fout.write("********************\n")
    fout.write("** tcpdump report **\n")
    fout.write("********************\n")
    with open(outfile, 'r') as fin:
        fout.write(fin.read())
    fout.write('\n\n\n')

######################
# Write summary info #
######################

# TBD - record key summary stats to a file in data/date dir so multiple reports can be summarized

#####################
# Print report file #
#####################

# Print the contents of the report file
with open(reportfile, 'r') as fin:
    print(fin.read())


os._exit(0)
