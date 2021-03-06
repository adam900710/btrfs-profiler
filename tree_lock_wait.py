#!/usr/bin/python2
# @lint-avoid-python-3-compatibility-imports
#
# # ./tree_lock_wait.py [-t <time_interval>] [-f <fsid>]
#
# <time_interval>: Sampling time interval, either in ns
#                  or with unit like "100ms" (default value)
# <fsid>:          Only catch events from fsid
#
# output will be csv format.

from __future__ import print_function
from bcc import BPF
from sys import stderr
from sys import argv
from collections import defaultdict
import uuid
import binascii
import getopt

text_bpf = '''
#include <uapi/linux/ptrace.h>
#define FSID_SIZE   16
struct data_t {
    u8  fsid[FSID_SIZE];
    u64 start_ns;
    u64 end_ns;
    u64 owner;
};
BPF_PERF_OUTPUT(events);
TRACEPOINT_PROBE(btrfs, btrfs_tree_read_lock)
{
    struct data_t data;
    bpf_probe_read(data.fsid, FSID_SIZE, args->fsid);
    data.start_ns = args->start_ns;
    data.end_ns = args->end_ns;
    data.owner = args->owner;
    events.perf_submit(args, &data ,sizeof(data));
    return 0;
}
TRACEPOINT_PROBE(btrfs, btrfs_tree_lock)
{
    struct data_t data;
    bpf_probe_read(data.fsid, FSID_SIZE, args->fsid);
    data.start_ns = args->start_ns;
    data.end_ns = args->end_ns;
    data.owner = args->owner;
    events.perf_submit(args, &data ,sizeof(data));
    return 0;
}
'''

def usage():
    print("%s [-t <time_interval>]" % (argv[0]))
    print("<time_interval> can be either in ns, or with unit like \"100ms\"")
    exit(1)

def is_fstree(owner):
    if owner == 5 or (owner >= 256 and owner <= (2 ** 64 - 256)):
        return True
    return False

def parse_time_interval(time_str):
    try:
        if ('s' not in time_str) or ('ns' in time_str):
            return int(time_str.split('ns')[0])
        if 'us' in time_str:
            return int(time_str.split('us')[0]) * 1000
        if 'ms' in time_str:
            return int(time_str.split('ms')[0]) * 1000 * 1000
        if 's' in time_str:
            return int(time_str.split('s')[0]) * 1000 * 1000 * 1000
    except ValueError as err:
        print(str(err))
        usage()

# TODO: Don't use such classification while have a good idea to output
# all the needed info
def get_owner_str(owner):
    if is_fstree(owner):
        return 'SUBVOL'
    if owner == 1:
        return 'TREE_ROOT'
    if owner == 2:
        return 'EXTENT_ROOT'
    return 'OTHER_ROOTS'


def process_event(cpu, data, size):
    event = b["events"].event(data)

    global start_time_set
    global start_time
    global end_time
    global time_interval
    global results 
    global fsid
    global fsid_set

    cur = int(event.start_ns / time_interval) * time_interval

    if fsid_set:
        current_fsid = uuid.UUID(binascii.hexlify(bytearray(event.fsid)))
        if current_fsid != fsid:
            return;

    if start_time_set:
        start_time = min(cur, start_time)
    else:
        start_time = cur 
        start_time_set = True 
    end_time = max(event.end_ns, end_time)

    while cur < event.end_ns:
        end_ns = min(event.end_ns, cur + time_interval)
        start_ns = max(cur, event.start_ns)

        if cur not in results:
            results[cur] = {}
            results[cur]['SUBVOL'] = 0
            results[cur]['TREE_ROOT'] = 0
            results[cur]['EXTENT_ROOT'] = 0
            results[cur]['OTHER_ROOTS'] = 0

        results[cur][get_owner_str(event.owner)] += end_ns - start_ns
        cur += time_interval

'''
output format (csv):
<aligned timestamp>, <tree root ns>, <extent root ns>, <subvol ns>, <other ns>
'''
def print_results():
    print(file=stderr)
    if not start_time_set:
        print("no data", file=stderr)
        exit(0)
    cur = start_time
    print("%s,%s,%s,%s,%s" % ("timestamp", "root", "extent", "subvol", "other"))
    while cur < end_time:
        if cur not in results:
            print("%d,%d,%d,%d,%d" % (cur - start_time, 0, 0, 0, 0))
        else:
            print("%d,%d,%d,%d,%d" % (cur - start_time,
                results[cur]['SUBVOL'],
                results[cur]['TREE_ROOT'],
                results[cur]['EXTENT_ROOT'],
                results[cur]['OTHER_ROOTS']))
        cur += time_interval
    
# default time interval is 100ms
time_interval = 100 * 1000 * 1000

# @results is a 2 dimension dict.
# [<aligned_timetamp>][<owner_str>] to access, no need to
# worry about non-exist key.
results = defaultdict(dict)

# To catch the first event time stamp
start_time_set = False
start_time = False

fsid_set = False

end_time = 0


try:
    opts, args = getopt.getopt(argv[1:], 't:f:')
except getopt.GetoptError as err:
    print(str(err), file=stderr)
    usage()

if len(args) != 0:
    usage()

for opt,arg in opts:
    if opt == '-t':
        time_interval = int(arg)
    if opt == '-f':
        fsid = uuid.UUID(arg)
        fsid_set = True

b = BPF(text = text_bpf)
b["events"].open_perf_buffer(process_event, page_cnt=64)
print("start recording", file=stderr)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print_results()
        exit(0)
