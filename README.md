# perf-linux
=======================

## Description
------------
The perf-linux tool collects, analyzes, and reports performance statistics over a short period of time to diagnose performance bottlenecks.  The script is designed to collect metrics for about 1 minute, analyze the collected data, and highlight any metrics that are likely to contribute to problems in red.

## Scope
-----
- Linux performance of a single host.
- Not intended for long running data collection, but can be used to anlayze and summarize sar output.

## Requirements
------------
- Python 2.7 or 3.x (source envs.local handles some of the portability issues)

- sysstat package (for collecting mpstat)
- iotop package (for collecting iotop)
- bind-utils package (for netstat_analyser to lookup DNS entries)
- tcpdump for packet capture and analysis
- tabulate Python module (included, Open Source license included)

## Platform Support
----------------
- Ubuntu 20
- Debian 10
- RHEL 7.x
- RHEL 6.x

Usage
-----

Run setup script to install deb/rpm packages for basic performance tools from standard repositories:
```
./setup.py
```

Source envs.local to set PYTHONPATH to the script directory for embedded modules (also )
```
. envs.local
```

Collect new data and analyze/report on data in in ./data/current
```
./perf-collect.py
./perf-analyze.py
```

Report on existing data in a specific directory containing output files like vmstat.out and sarA.out
```
./perf-analyze.py -d ./data/directory_with_commands
```

Sample Report
-------------

```
$./perf-analyze.py -d ./data/120816_145051
metric         avg       sd    min       max  description
---------  -------  -------  -----  --------  -----------------------------------------------
usr           37       17.7      0      98    % CPU for user processes
sys            6        3.2      0      18    % CPU for system processes
wait           0        0        0       0    % CPU wait
r             10       13.5      0      86    run queue
b              0        0        0       1    processes in uninterruptible sleep
cs         97485    57617      141  278192    CPU context switch/s
in         45711    21161      206  106845    interrupts/s
si             0        0        0       0    swap in from disk /s
so             0        0        0       0    swap out to disk /s
bi             0        0        0       4    block read /s
bo           152      607        0    3668    block write /s
pswpin/s       0        0        0       0    swap pages in /s
pswpout/s      0        0        0       0    swap pages out /s
pgpgin/s       0        0        0       4    KB paged in from disk /s
pgpgout/s    156      618        0    3813    KB paged out to disk /s
fault/s    21800    12830     1215   95225    major+minor page faults /s
majflt/s       0        0        0       0    page faults that required loading from disk /s
pgfree/s   23510    15678      569   99256    pages placed on free list /s
pgscank/s      0        0        0       0    pages scanned by kswapd /s
pgscand/s      0        0        0       0    pages scanned directly /s
pgsteal/s      0        0        0       0    pages reclaimed from cache to satisfy demand
%vmeff         0        0        0       0    pgsteal/pgscan=virtual memory efficiency
file-nr     2435       42     2304    2560    number of file handles
inode-nr   85610     1853    83322   86909    number of inode handlers
proc/s        13.5     11        0     110.1  tasks created /s
plist-sz    1097        5     1085    1097    number of tasks in task list
tps            5       55        0     988    transfers per second to physical devices (IOPS)
rtps           0        0        0       2    read IOPS
wtps          44      160        0     988    write IOPS
bread/s        0        1        0      16    block reads (512B) /s
bwrtn/s      625     2461        0   15250    block writes (512B) /s

adapter    metric    avg     sd      min    max      description
---------  --------  ------  ------  -----  -------  -------------
lo         rxdrop/s  0.0     0.0     0.0    0.0
lo         txerr/s   0.0     0.0     0.0    0.0
lo         txdrop/s  0.0     0.0     0.0    0.0
lo         txkB/s    4156.0  855.5   0.0    6063.6
lo         rxkB/s    4156.0  855.5   0.0    6063.6
lo         rxerr/s   0.0     0.0     0.0    0.0
lo         rxpck/s   5748.0  1644.1  0.0    12086.0
lo         txpck/s   5748.0  1644.1  0.0    12086.0
lo         rxmcst/s  0.0     0.0     0.0    0.0

eth1       rxdrop/s  0.0     0.0     0.0    0.0
eth1       txerr/s   0.0     0.0     0.0    0.0
eth1       txdrop/s  0.0     0.0     0.0    0.0
eth1       txkB/s    0.0     0.0     0.0    0.1
eth1       rxkB/s    1.6     0.5     0.5    3.2
eth1       rxerr/s   0.0     0.0     0.0    0.0
eth1       rxpck/s   22.6    7.5     7.1    41.0
eth1       txpck/s   0.0     0.1     0.0    2.1
eth1       rxmcst/s  0.0     0.0     0.0    0.0

eth0       rxdrop/s  0.0     0.0     0.0    0.0
eth0       txerr/s   0.0     0.0     0.0    0.0
eth0       txdrop/s  0.0     0.0     0.0    0.0
eth0       txkB/s    1927.0  600.1   0.3    3354.6
eth0       rxkB/s    3362.0  1082.1  0.3    5689.6
eth0       rxerr/s   0.0     0.0     0.0    0.0
eth0       rxpck/s   2939.0  787.0   4.0    4505.2
eth0       txpck/s   2403.0  571.7   3.0    3483.3
eth0       rxmcst/s  0.0     0.0     0.0    0.0


************************
** netstat -an report **
************************
TCP_STATE                 Count
LISTEN                    29
ESTABLISHED               200
SYN_SENT                  0
SYN_RECV                  0
FIN_WAIT                  0
FIN_WAIT2                 0
TIME_WAIT                 175

Inbound:
Local IP                  Local port      Count
localhost                 5432            66
localhost                 11002           10
localhost                 9463            9
192.168.0.50              5672            8
localhost                 4369            5
localhost                 8983            1
localhost                 5672            1
192.168.0.50              22              1
192.168.0.50              15672           1

Remote hosts connecting in:
Remote IP                 Local port      Count
192.168.0.51              5672            4
192.168.0.52              22              1

Outbound:
Foreign IP                Foreign port    Count
```

## Future Enhancements
-------------------
- Configuration file - set data collection options and adjust default tresholds for identifying issues 
- Print filesystem report w/ high utilizations (inodes and capacity).  Look for filesystem overmount issues.
- Track ingress/egress bytes in tcpdump analysis (or per IP)
- Look at /proc/meminfo.  Report high swap.
- Create function to print formatted headers for each section
- process iseg/s, oseg/s, orsts/s
- Add graceful exits if input files do not exist
- Create an external config file to store sar fields to capture so it can be read in to:
  - identify fields to report on
  - set thresholds for each field
  - store descriptions of each field
- Create profiles directory to store collection/reporting profile configurations to override defaults
- Ability to process sar binary files from regular sysstat collections
- Improve and integrate sar -A converter script to generate parsable sar.data file
- Collector script to record process info such as start/stop times in epoch and return code
- Use timing info in report headers to print start/duration
- Add blktrace
- Write machine readable summary info from analysis to a file (json)
- Integrate menu (dialog) for selecting collection profiles
- Integrate menu (text) for listing data collection w/ summary info
