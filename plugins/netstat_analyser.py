#!/usr/bin/env python

import os
import sys
import re
import getopt
import subprocess

opt_name_resolution = False

data_dir = False
max_results = 50

ip_to_hostname_cache = {}

# global regex to compile
re_tcp = re.compile(r"^tcp")
re_ip_port = re.compile(r"^(.*)[\.:](.*?)$")
re_trim_ip = re.compile(r"^.*:")

def get_data():
    if data_dir:
        f = os.path.join(data_dir, 'netstat_an.out')
        if not os.path.exists(f):
            print("Cannot find input netstat file, exiting")
            sys.exit(1)
        with open(f) as fh:
            netstat_output = fh.read()
    else:
        pid = subprocess.Popen(('netstat', '-an'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        netstat_output = pid.communicate()[0]

    if data_dir:
        f = os.path.join(data_dir, 'ifconfig_a.out')
        if not os.path.exists(f):
            print("Cannot find input ifconfig -a file, exiting")
            sys.exit(1)
        with open(f) as fh:
            ifconfig_output = fh.read()
    else:
        pid = subprocess.Popen(('ifconfig', '-a'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ifconfig_output = pid.communicate()[0]

    if data_dir:
        f = os.path.join(data_dir, 'uname.out')
        if not os.path.exists(f):
            print("Cannot find input uname file, exiting")
            sys.exit(1)
        with open(f) as fh:
            uname_output = fh.read()
    else:
        pid = subprocess.Popen('uname', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        uname_output = pid.communicate()[0]
    kernel = uname_output.strip()

    return netstat_output, ifconfig_output, kernel


def get_ips(kernel, ifconfig_input):

    host_ips = []

    if (kernel == "Linux" or kernel == "Darwin"):
        re_interface = re.compile(r"^(\S.*?):")
        re_inet_addr = re.compile(r"inet addr:(.*?)\s")
        re_inet = re.compile(r"inet (.*?)\s")
        re_inet6 = re.compile(r"inet6 (.*?)\s")

        for line in ifconfig_input.splitlines():
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

    if kernel == "AIX":
        re_interface = re.compile(r"^()\w+):")
        re_inet = re.compile(r"inet\s(.*?)\snetmask\s0x(.{8})\sbroadcast\s(.*)$")

        for line in ifconfig_input.splitlines():
            line.strip()

            result = re_interface.search(line)
            if result is not None:
                interface = result.group(1)
                continue
            else:
                result = re_inet.search(line)
                if result is not None:
                    ip = result.group(1)
                    host_ips.append(ip)
                    continue

    return host_ips


def get_ips_ports(netstat_input, host_ips):
    host_ips_ports_idx = {}

    for line in netstat_input.splitlines():
        line.strip()

        # skip if line doesn't start with "tcp"
        result = re_tcp.match(line)
        if result is None:
            continue

        # split packet info into components
        packet = line.split()

        # Skip if state is not LISTEN
        if packet[5] != 'LISTEN':
            continue

        # if made it this far, line starts w/ "tcp" and packet[5] == LISTEN
        # packet 3 is the local IP/port listening

        result = re_ip_port.match(packet[3])
        if result is None:
            print("WARN: " + line)
            continue

        (ip_local, port_local) = result.group(1, 2)

        ip_local = re_trim_ip.sub('', ip_local)

        if (ip_local == '*') or (ip_local == '0.0.0.0'):
            for ip in host_ips:
                ip_local = ip + ':' + port_local
                host_ips_ports_idx[ip_local] = True
        else:
            ip_local = ip_local + ':' + port_local
            host_ips_ports_idx[ip_local] = True

    return host_ips_ports_idx


def analyze_netstat(netstat_input, host_ips_ports_idx, host_ips):
    # populate index of host ips so ESTABLISHED connections can be checked efficiently

    host_ips_idx = {}
    inbound = {}
    outbound = {}
    local = {}
    remote = {}
    tcp_unknown = []

    for ip in host_ips:
        host_ips_idx[ip] = True

    tcp_counters = {
        'listen': 0,
        'established': 0,
        'established_inbound': 0,
        'established_outbound': 0,
        'established_local': 0,
        'established_remote': 0,
        'syn_sent': 0,
        'syn_recv': 0,
        'fin_wait': 0,
        'fin_wait2': 0,
        'time_wait': 0,
        'close_wait': 0
    }

    for line in netstat_input.splitlines():
        line.strip()
        result = re_tcp.match(line)
        if result is None:
            continue

        packet = line.split()

        if packet[5] != 'ESTABLISHED':
            tcp_counters['listen'] += 1 if packet[5] == 'LISTEN' else False
            tcp_counters['syn_sent'] += 1 if packet[5] == 'SYN_SENT' else False
            tcp_counters['syn_recv'] += 1 if packet[5] == 'SYN_RECV' else False
            tcp_counters['fin_wait'] += 1 if packet[5] == 'FIN_WAIT' else False
            tcp_counters['fin_wait2'] += 1 if packet[5] == 'FIN_WAIT2' else False
            tcp_counters['time_wait'] += 1 if packet[5] == 'TIME_WAIT' else False
            tcp_counters['close_wait'] += 1 if packet[5] == 'CLOSE_WAIT' else False
            continue
        tcp_counters['established'] += 1

        # parse packet[3], which is the 1st column of IP/port
        result = re_ip_port.match(packet[3])
        if result is None:
            print("WARN: " + line)
            continue
        (ip1, port1) = result.group(1, 2)
        ip1 = re_trim_ip.sub('', ip1)
        ip_port1 = ip1 + ':' + port1

        # parse packet[4], which is the 2nd column of IP/port
        result = re_ip_port.match(packet[4])
        if result is None:
            print("WARN: " + line)
            continue
        (ip2, port2) = result.group(1, 2)
        ip2 = re_trim_ip.sub('', ip2)
        ip_port2 = ip2 + ':' + port2

        # Determine "direction" of packet based on local ips and listening ports
        if ip1 in host_ips_idx and ip2 in host_ips_idx:
            # Both IPs local: local connection
            tcp_counters['established_local'] += 1
            if ip_port1 in host_ips_ports_idx:
                if ip_port1 in local:
                    local[ip_port1] += 1
                else:
                    local[ip_port1] = 1
            elif ip_port2 in host_ips_ports_idx:
                if ip_port2 in local:
                    local[ip_port2] += 1
                else:
                    local[ip_port2] = 1
            else:
                tcp_unknown.append(packet)
                continue

        elif ip_port1 in host_ips_ports_idx:
            # ip2 is remote connecting to local ip_port1

            # process local/inbound information
            tcp_counters['established_inbound'] += 1
            if ip_port1 in inbound:
                inbound[ip_port1] += 1
            else:
                inbound[ip_port1] = 1

            # process remote information for inbound connection
            tcp_counters['established_remote'] += 1

            # group inbound remote by remote ip and local port
            remote_ip_port = ip2 + ':' + port1
            if remote_ip_port in remote:
                remote[remote_ip_port] += 1
            else:
                remote[remote_ip_port] = 1

        elif ip_port2 in host_ips_ports_idx:
            # ip1 is remote connecting to local ip_port2

            # process local/inbound information
            tcp_counters['established_inbound'] += 1
            if ip_port2 in inbound:
                inbound[ip_port2] += 1
            else:
                inbound[ip_port2] = 1

            # group inbound remote by remote ip and local port
            remote_ip_port = ip1 + ':' + port2
            if remote_ip_port in remote:
                remote[remote_ip_port] += 1
            else:
                remote[remote_ip_port] = 1

        else:
            # outbound connection
            tcp_counters['established_outbound'] += 1

            if ip1 in host_ips_idx:
                # ip1 is local, ip2 is remote host connecting to
                if ip_port2 in outbound:
                    outbound[ip_port2] += 1
                else:
                    outbound[ip_port2] = 1
            elif ip2 in host_ips_idx:
                # ip2 is local, ip1 is remote host connecting to
                if ip_port1 in outbound:
                    outbound[ip_port1] += 1
                else:
                    outbound[ip_port1] = 1
            else:
                tcp_unknown.append(packet)
                continue

    return (tcp_counters, inbound, outbound, local, remote, tcp_unknown)

def print_tcp_record(ip_port, count, kernel):
    result = re_ip_port.match(ip_port)
    (ip, port) = result.group(1, 2)
    if opt_name_resolution == True:
        ip = lookup_ip_in_dns(ip, kernel)
    print('{0:<25} {1:<15} {2:<10}'.format(ip, port, count))

def print_report(kernel, tcp_counters, inbound, outbound, local, remote, tcp_unknown):
    print('{0:<15} {1:<8}'.format('TCP_STATE', 'COUNT'))
    print('{0:<15} {1:<8}'.format('LISTEN', tcp_counters['listen']))
    print('{0:<15} {1:<8}'.format('ESTABLISHED', tcp_counters['established']))
    print('{0:<15} {1:<8}'.format('SYN_SENT', tcp_counters['syn_sent']))
    print('{0:<15} {1:<8}'.format('SYN_RECV', tcp_counters['syn_recv']))
    print('{0:<15} {1:<8}'.format('FIN_WAIT', tcp_counters['fin_wait']))
    print('{0:<15} {1:<8}'.format('FIN_WAIT2', tcp_counters['fin_wait2']))
    print('{0:<15} {1:<8}'.format('TIME_WAIT', tcp_counters['time_wait']))
    print('{0:<15} {1:<8}'.format('CLOSE_WAIT', tcp_counters['close_wait']))

    print("\nInbound: " + str(tcp_counters['established_inbound']))
    print('{0:<25} {1:<15} {2:<10}'.format('Local IP', 'Local port', 'Count'))
    count = 0
    for key in sorted(inbound, key=inbound.get, reverse=True):
        print_tcp_record(key, inbound[key], kernel)
        count += 1
        if count >= max_results:
            break

    print("\nLocal connections: " + str(tcp_counters['established_local']))
    print('{0:<25} {1:<15} {2:<10}'.format('Local IP', 'Local port', 'Count'))
    count = 0
    for key in sorted(local, key=local.get, reverse=True):
        print_tcp_record(key, local[key], kernel)
        count += 1
        if count >= max_results:
            break

    print("\nRemote hosts connecting in: " + str(tcp_counters['established_remote']))
    print('{0:<25} {1:<15} {2:<10}'.format('Remote IP', 'Local port', 'Count'))
    count = 0
    for key in sorted(remote, key=remote.get, reverse=True):
        print_tcp_record(key, remote[key], kernel)
        count += 1
        if count >= max_results:
            break

    print("\nOutbound: " + str(tcp_counters['established_outbound']))
    print('{0:<25} {1:<15} {2:<10}'.format('Foreign IP', 'Foreign port', 'Count'))
    count = 0
    for key in sorted(outbound, key=outbound.get, reverse=True):
        print_tcp_record(key, outbound[key], kernel)
        count += 1
        if count >= max_results:
            break

    tcp_unknown_count = len(tcp_unknown)
    if tcp_unknown_count > 0:
        print("\nPackets not analyzed: " + str(tcp_unknown_count))
        for packet in tcp_unknown:
            print(packet)


def lookup_ip_in_dns(ip, kernel):

    # TODO - Does this cache persist for each call or does it need to be global?
    global ip_to_hostname_cache
    # TODO - Probably just need get_data command to populate global ip_to_hostname_cache.
    if ip in ip_to_hostname_cache:
        print("debug: found " + ip + " in dict cache")
        return ip_to_hostname_cache[ip]

    # Run host command to lookup IP.  Get output and return code.
    pid = subprocess.Popen(('host', ip), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lookup_output = pid.communicate()[0]
    rc = pid.returncode

    if rc == 0:
        # host/lookup suceeded
        # get first line of output in case multiples are returned and strip eol char
        line = lookup_output.splitlines()[0]
        line.strip()

        if kernel == 'Linux' or kernel == 'Darwin':
            # FQDN in last element when looking up IP
            hostname = line.split()[-1]
            # truncate FQDN to short name for reporting
            hostname = hostname.split('.')[0]
        elif kernel == 'AIX':
            # AIX puts FQDN 1st when looking up IP
            hostname = line.split()[0]
            # truncate FQDN to short name for reporting
            hostname = hostname.split('.')[0]
        else:
            # OS not known, set ip to hostname
            hostname = ip

        # Set dict cache to avoid subsequent lookups
        ip_to_hostname_cache[ip] = hostname
        return hostname

    else:
        # DNS lookup failed, just return IP
        return ip

def main():
    (netstat_output, ifconfig_output, kernel) = get_data()
    host_ips = get_ips(kernel, ifconfig_output)
    host_ips_ports_idx = get_ips_ports(netstat_output, host_ips)
    (tcp_counters, inbound, outbound, local, remote, tcp_unknown) = analyze_netstat(netstat_output, host_ips_ports_idx, host_ips)
    print_report(kernel, tcp_counters, inbound, outbound, local, remote, tcp_unknown)

if __name__ == '__main__':
    main()

