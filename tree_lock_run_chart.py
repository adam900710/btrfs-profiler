#!/usr/bin/python3
# @lint-avoid-python-3-compatibility-imports

from __future__ import print_function
from bcc import BPF
from sys import stderr

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

def is_fstree(owner):
    if owner == 5 or (owner >= 256 and owner <= (2 ** 64 - 256)):
        return True
    return False

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


'''
Sparse dict where access to hole (non-exist) key will return 0
other than raise an exception
'''
class sparse_dict:
    data_dict = {}
    def __init__(self):
        self.data_dict = {}

    def __getitem__(self, key):
        if key not in self.data_dict:
            return 0
        return self.data_dict[key]

    def __setitem__(self, key, value):
        self.data_dict[key] = value;

    def __contains__(self, key):
        return (key in self.data_dict)


def process_event(cpu, data, size):
    event = b["events"].event(data)

    global start_time_set
    global start_time
    global end_time
    global time_interval
    global results 

    cur = int(event.start_ns / time_interval) * time_interval
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
            results[cur] = sparse_dict()

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
        exit()
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
results = sparse_dict()

# To catch the first event time stamp
start_time_set = False
start_time = False

end_time = 0


b = BPF(text = text_bpf)
b["events"].open_perf_buffer(process_event, page_cnt=64)
print("start recording", file=stderr)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print_results()
exit()
