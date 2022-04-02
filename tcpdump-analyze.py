#!/usr/bin/env python3

import os
import signal
import subprocess
import sys
from time import time, sleep, localtime, strftime
import getopt
import re

# modules from parent directory (export PYTHONPATH=<parent_dir>)
#sys.path.append('..')
from mod_stats import *
from tabulate import tabulate

def usage(exit_code=0):
    """Display help message if -h option used or invalid syntax."""
    print(os.path.basename(__file__) + ' -r <input_file>')
    print("")
    sys.exit(exit_code)

# default arguments
base_dir = os.path.dirname(os.path.abspath(__file__))
datetime = strftime("%Y-%m-%d_%H%M%S", localtime())
arg_dict = {}
arg_dict['input_file'] = None

try:
    opts, args = getopt.getopt(sys.argv[1:], "hr:")
except getopt.GetoptError:
    usage(1)
for opt, arg in opts:
    if opt == '-h':
        usage()
    elif opt in ("-r"):
        arg_dict['input_file'] = arg

if not arg_dict['input_file']:
    print('ERROR: -r is required')
    usage(1)

if not os.path.exists(arg_dict['input_file']):
    print('ERROR: input file {0} does not exist'.format(arg_dict['input_file']))
    usage(1)

def get_local_ips():
    host_ips = []
    re_interface = re.compile(r"^(\S.*?):")
    re_inet_addr = re.compile(r"inet addr:(.*?)\s")
    re_inet = re.compile(r"inet (.*?)\s")
    re_inet6 = re.compile(r"inet6 (.*?)\s")

    # Check for ifconfig_a.out file in same directory as input file (more portable)
    input_file_dir = os.path.dirname(os.path.abspath(arg_dict['input_file']))
    ifconfig_path = os.path.join(input_file_dir, 'ifconfig_a.out')
    if os.path.exists(ifconfig_path):
        print('Using ifconfig -a output from file: {0}'.format(ifconfig_path))
        with open(ifconfig_path) as fh:
            ifconfig_stdout = fh.read()
    else:
        pid = subprocess.Popen(('ifconfig', '-a'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        ifconfig_stdout = pid.communicate()[0]

    for line in ifconfig_stdout.splitlines():
        line.strip()
        result = re_interface.search(line)
        if result is not None:
            interface = result.group(1)
            continue

        result = re_inet.search(line)
        if result is not None:
            ip = result.group(1)
            host_ips.append(ip)
            continue

        result = re_inet6.search(line)
        if result is not None:
            ip = result.group(1)
            host_ips.append(ip)
            continue

        result = re_inet_addr.search(line)
        if result is not None:
            ip = result.group(1)
            host_ips.append(ip)
            continue
    return set(host_ips)

def get_ip_port(ip_port):
    ip_port_list = ip_port.split('.')
    port = ip_port_list[-1]
    ip = '.'.join(ip_port_list[0:-1])
    return(ip, port)


# get local IPs to determine ingress/egress
host_ips = get_local_ips()

# stat variables
conversations = {}  # conversations collect packet counts, keys = normalized ip1:port1;ip2:port2)
talkers = {}  # talkers collect normalized ip combinations (no port), keys 
protos = set()
proto_count = {}
ip_to_hostname_cache = {}
datetime_start = False
datetime_end = 0
count_total = 0
count_ingress = 0
count_egress = 0
count_internal = 0
count_unknown = 0
count_rst = 0
count_fin = 0
count_syn = 0
count_syna = 0
# Can use these if using netstat to more accurately determine direction
# count_syn_recv = 0
# count_syn_sent = 0
# count_rst_recv = 0
# count_rst_sent = 0

cmd = ['tcpdump', '-r', arg_dict['input_file'], '-nn', '-tt']

process = subprocess.Popen(cmd,stdout=subprocess.PIPE, universal_newlines=True)
while True:
    line = process.stdout.readline()
    if not line:
        break
    count_total += 1
    flag_syn_set = 0
    flag_ack_set = 0
    packet = line.split()

    # Grab packet timings (start, end is set to current for each packet)
    if not datetime_start:
        datetime_start = packet[0]
    datetime_end = packet[0]

    # parse based on protocol determined by field 5 (Flags=TCP, ICMP)
    if packet[1] == 'IP':
        if packet[5] == 'UDP,':
            proto = 'UDP'
        elif packet[5] == 'ICMP':
            proto = 'ICMP'
        else:
            proto = 'TCP'
    else:
        # ARP, LLDP, ST, IP6, ICMP6
        proto = packet[1][:-1]  # remove ending comma (might need to check it really is a comma)

    if proto not in protos:
        protos.add(proto)
        proto_count[proto] = 0

    proto_count[proto] += 1

    if packet[1] != 'IP':
        # too many other protocols to decode this way so just skip
        continue

    packet[4] = packet[4][:-1] #remove ending ":" from dest IP
    ip_src, port_src = get_ip_port(packet[2])
    ip_dest, port_dest = get_ip_port(packet[4])

    # Figure out direction and normalize conversations for counting
    # It would be better to have a netstat -an report with listening ports to use here
    direction = "unknown"
    if ip_src in host_ips and ip_dest in host_ips:
        direction = "internal"
        count_internal += 1
        if ip_src > ip_dest:
            conversation = '{0}:{1};{2}:{3}'.format(ip_src, port_src, ip_dest, port_dest)
            talker = '{0};{1}'.format(ip_src, ip_dest)
        else:
            conversation = '{0}:{1};{2}:{3}'.format(ip_dest, port_dest, ip_src, port_src)
            talker = '{0};{1}'.format(ip_dest, ip_src)
    elif ip_src in host_ips:
        direction = "egress"
        count_egress += 1
        conversation = '{0}:{1};{2}:{3}'.format(ip_src, port_src, ip_dest, port_dest)
        talker = '{0};{1}'.format(ip_src, ip_dest)
    elif ip_dest in host_ips:
        direction = "ingress"
        count_ingress += 1
        conversation = '{0}:{1};{2}:{3}'.format(ip_dest, port_dest, ip_src, port_src)
        talker = '{0};{1}'.format(ip_dest, ip_src)
    else:
        direction = "unknown"
        count_unknown += 1
        if ip_src > ip_dest:
            conversation = '{0}:{1};{2}:{3}'.format(ip_src, port_src, ip_dest, port_dest)
            talker = '{0};{1}'.format(ip_src, ip_dest)
        else:
            conversation = '{0}:{1};{2}:{3}'.format(ip_dest, port_dest, ip_src, port_src)
            talker = '{0};{1}'.format(ip_dest, ip_src)

    if conversation not in conversations:
        conversations[conversation] = {
            'count': 0
        }

    if talker not in talkers:
        talkers[talker] = {
            'count': 0,
            'syn': 0,
            'syna': 0,
            'fin': 0,
            'rst': 0,
            'ack': 0,
            'none': 0,
            'push': 0
        }

    talkers[talker]['count'] += 1
    conversations[conversation]['count'] += 1

    # print(packet)

    # Some IP packets like syslog still make it this far
    if packet[5] != 'Flags':
        # print(packet)
        continue

    # # Last resort for valid TCP
    # if len(packet) < 6:
    #     print(packet)
    #     continue

    if proto == 'TCP':
        # field 6 has TCP flags in square brackets
        flags = packet[6][:-1]  # remove ending comma (might need to check it really is a comma)
        if flags == '[.]':
            if packet[7] == 'ack' or packet[9] == 'ack':
                talkers[talker]['ack'] += 1
            else:
                talkers[talker]['none'] += 1
        elif flags == '[P.]':
            talkers[talker]['push'] += 1
        elif flags == '[S]':
            talkers[talker]['syn'] += 1
            count_syn += 1
        elif flags == '[S.]':
            talkers[talker]['syna'] += 1
            count_syna += 1
        elif flags == '[R]':
            talkers[talker]['rst'] += 1
            count_rst += 1
        elif flags == '[F.]':
            talkers[talker]['fin'] += 1
            count_fin += 1
        # else:
        #     print(packet)

# Calculate duration to be used w/ packet rates
duration_sec = float(datetime_end) - float(datetime_start)

# Function to sort talker and converstion counts
def keyfunc(tup): 
    _key, d = tup
    return d['count']

talker_max_report = 25
print('Talker Summary (top {0}):'.format(talker_max_report))
count = 0
stats = []
row = ['talker', 'count', 'syn', 'syna', 'fin', 'rst', 'ack', 'push', 'none']
stats.append(row)
for talker, _subd in sorted(talkers.items(), key=keyfunc, reverse=True):
    # if talkers[talker]['count'] < 500:
    #     continue
    talker_print = talker.replace(';', ' ')
    row = [talker_print, talkers[talker]['count'], talkers[talker]['syn'], talkers[talker]['syna'],
        talkers[talker]['fin'], talkers[talker]['rst'], talkers[talker]['ack'],
        talkers[talker]['push'], talkers[talker]['none']]
    stats.append(row)

    count += 1
    if count >= talker_max_report:
        break
print(tabulate(stats, headers="firstrow"))
print('')

conv_max_report = 25
print('Conversation Summary (top {0}):'.format(conv_max_report))
count = 0
stats = []
row = ['conversation', 'count', 'pps']
stats.append(row)
for conversation, _subd in sorted(conversations.items(), key=keyfunc, reverse=True):
    # if conversations[conversation]['count'] < 500:
    #     continue
    conv_print = conversation.replace(';', ' ')
    row = [conv_print, conversations[conversation]['count'], divide(conversations[conversation]['count'], duration_sec, 0)]
    stats.append(row)
    count += 1
    if count >= conv_max_report:
        break
print(tabulate(stats, headers="firstrow"))
print('')

# Initialize list for storing rows for the report and add header row
print('Total packet counts:')
print('duration (sec): {0:.2f}'.format(duration_sec))
stats = []
row = ['', 'Total', 'pps']
stats.append(row)
row = ['total', count_total, divide(count_total, duration_sec, 0)]
stats.append(row)
row = ['ingress', count_ingress, divide(count_ingress, duration_sec, 0)]
stats.append(row)
row = ['egress', count_egress, divide(count_egress, duration_sec, 0)]
stats.append(row)
row = ['internal', count_internal, divide(count_internal, duration_sec, 0)]
stats.append(row)
row = ['unknown', count_unknown, divide(count_unknown, duration_sec, 0)]
stats.append(row)
row = ['SYN', count_syn, divide(count_syn, duration_sec, 1)]
stats.append(row)
row = ['SYN-ACK', count_syna, divide(count_syna, duration_sec, 1)]
stats.append(row)
row = ['FIN', count_fin, divide(count_fin, duration_sec, 1)]
stats.append(row)
count_rst_print = count_rst
if count_rst_print > 0:
    count_rst_print = fmtRed(count_rst)
row = ['RST', count_rst_print, divide(count_rst, duration_sec, 1)]
stats.append(row)
print(tabulate(stats, headers="firstrow"))
print('')

# sys.exit(0)
print('Protocol Summary:')
print('{0:<10} {1}'.format('Protocol', 'Count'))
for proto in proto_count:
    print('{0:<10} {1}'.format(proto, proto_count[proto]))
print('')
