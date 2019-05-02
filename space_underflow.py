#!/usr/bin/python2
# @lint-avoid-python-3-compatibility-imports
#
# # ./tree_lock_wait.py [-f <fsid>] [-t data|metadata|system] [-o <output>]
#                       [-b] <member>
#
#
# -f <fsid>:        Only catch events from fsid
# -t data|metadata|system:
#                   Only catch events for certain block group type
# -o <output>       Output full events with backtrace to file <output>
# <target>:         Which function to trace
#                   Supported members are (need kernel patch):
#                     update_bytes_may_use
#                     update_bytes_pinned
#

from __future__ import print_function
from bcc import BPF
from sys import stderr
from sys import stdout
from sys import argv
from collections import defaultdict
import uuid
import binascii
import getopt

text_bpf = '''
#include <uapi/linux/ptrace.h>
#define FSID_SIZE   16
struct data_t {
    u64 timestamp;
    u8  fsid[FSID_SIZE];
    u64 type;
    u64 old;
    s64 diff;
    s64 stack_id;
};

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 1024);

TRACEPOINT_PROBE(btrfs, ##FUNC_NAME##)
{
    struct data_t data;

    bpf_probe_read(data.fsid, FSID_SIZE, args->fsid);
    data.stack_id = stack_traces.get_stackid(args, BPF_F_REUSE_STACKID);
    data.type = args->type;
    data.old = args->old;
    data.diff = args->diff;
    data.timestamp = bpf_ktime_get_ns();

    events.perf_submit(args, &data ,sizeof(data));
    return 0;
}
'''

usage_str='''
# %s [-f <fsid>] [-t data|metadata|system] [-o <output>]
                      [-b] <member>


-f <fsid>:        Only catch events from fsid
-t data|metadata|system:
                  Only catch events for certain block group type
-o <output>       Output full events with backtrace to file <output>
<target>:         Which function to trace
                  Supported members are (need kernel patch):
                    update_bytes_may_use
                    update_bytes_pinned
'''
def usage():
    print(usage_str % argv[0])
    exit(1)

BTRFS_BLOCK_GROUP_TYPES = {
        "DATA" : 1 << 0,
        "SYSTEM" : 1 << 1,
        "METADATA" : 1 << 2
}

bg_type = BTRFS_BLOCK_GROUP_TYPES["DATA"] |\
          BTRFS_BLOCK_GROUP_TYPES["SYSTEM"] |\
          BTRFS_BLOCK_GROUP_TYPES["METADATA"]

target_fsid = None
output = None
target_func = None
last_timestamp = 0

# fs_dict = {"<FSID>" : one_fs}
# one_fs = {
#         "DATA" : [],
#         "METADATA" : [],
#         "SYSTEM" : [],
# }
fs_dict = {}

def parse_bg_types(bg_str):
    types = bg_str.upper().split('|')
    ret = 0
    for i in types:
        one_type = i.replace(' ', '')
        if one_type in BTRFS_BLOCK_GROUP_TYPES:
            ret |= BTRFS_BLOCK_GROUP_TYPES[one_type]
        else:
            print("'%s' is not a valid block group type" % one_type)
            usage()
            exit(1)
    return ret

def generate_stack(event):
    ret = []
    if event.stack_id < 0:
        return ["no stack due to stack trace size limit"]
    for stack in stack_traces.walk(event.stack_id):
        sym = b.ksym(stack, show_offset=True)
        ret.append(sym)
    return ret

def process_event(cpu, data, size):
    global bg_type
    global target_fsid

    event = b["events"].event(data)
    fsid = uuid.UUID(binascii.hexlify(bytearray(event.fsid)))

    if target_fsid and fsid != target_fsid:
        return;
    if (event.type & bg_type) == 0:
        return
    if event.type == BTRFS_BLOCK_GROUP_TYPES["DATA"]:
        cur_type = "DATA"
    elif event.type == BTRFS_BLOCK_GROUP_TYPES["SYSTEM"]:
        cur_type = "SYSTEM"
    else:
        cur_type = "METADATA"

    tmp = {}
    tmp["timestamp"] = event.timestamp
    tmp["old"] = event.old
    tmp["diff"] = event.diff
    tmp["stack"] = generate_stack(event)
    tmp["type"] = cur_type
    if str(fsid) not in fs_dict:
        fs_dict[str(fsid)] = {}
        fs_dict[str(fsid)]["DATA"] = []
        fs_dict[str(fsid)]["METADATA"] = []
        fs_dict[str(fsid)]["SYSTEM"] = []
        fs_dict[str(fsid)]["ALL"] = []
    fs_dict[str(fsid)][cur_type].append(tmp)
    fs_dict[str(fsid)]["ALL"].append(tmp)

def print_one_event(output, event, backtrace=False):
    print("timestamp=%u type=%s old=%u diff=%u" % (event["timestamp"], event["type"], \
            event["old"], event["diff"]), file=output)
    if backtrace:
        print("backtrace:", file=output)
        for sym in event["stack"]:
            print("  %s" % sym, file=output)
        print(file=output)

def report_underflow(fsid, result_list, name):
    if len(result_list) == 0:
        return
    last_good_index = [0, 0]
    cur = result_list[0]["old"]
    for index, event in enumerate(result_list, start = 0):
        if event["diff"] < 0 and event["diff"] + cur < 0:
            # underflow detected, try to show the history
            print("%s underflow detected for fsid %s" % (name, fsid))
            if last_good_index[1] < index:
                print("printing events from last good checkpoints:")

                if last_good_index[1] != index - 1:
                    start_index = last_good_index[1]
                else:
                    # Previous event is good, need to another checkpoint
                    start_index = last_good_index[0]

                for i in result_list[start_index : index + 1]:
                    print_one_event(stdout, i, backtrace=True)
            else:
                print("offending event:")
                print_one_event(stdout, event, backtrace=True)
            return
        cur += event["diff"]

        # update check points
        if cur == 0:
            last_good_index[0] = last_good_index[1]
            last_good_index[1] = index
    print("no underflow detected for profile %s of fsid %s" % (name, fsid))
                
def by_timestamp(event):
    return event["timestamp"]

def print_fs_dict():
    for fsid in fs_dict:
        print_one_fs(fsid, fs_dict[fsid])

def print_one_fs(fsid, results):
    # Sort all results according to timestamp first
    results["DATA"].sort(key = by_timestamp)
    results["METADATA"].sort(key = by_timestamp)
    results["SYSTEM"].sort(key = by_timestamp)
    results["ALL"].sort(key = by_timestamp)
    if not output:
        print("print all trace events for fs %s:" % (fsid))
        for i in results["ALL"]:
            print_one_event(stdout, i)
        return
    if len(results) != 0:
        print("fsid: %s" % (fsid), file=fd)
    for i in results["ALL"]:
        print_one_event(fd, i, backtrace=True)

    # Check if any METADATA/DATA/SYSTEM underflows
    report_underflow(fsid, results["DATA"], "DATA")
    report_underflow(fsid, results["METADATA"], "METADATA")
    report_underflow(fsid, results["SYSTEM"], "SYSTEM")

try:
    opts, args = getopt.getopt(argv[1:], "f:t:o:")
except getopt.GetoptError as err:
    print(str(err), file=stderr)
    usage()

if len(args) != 1:
    usage()

target_func = args[0]

for opt,arg in opts:
    if opt == '-t':
        bg_type = parse_bg_types(arg)
    if opt == '-f':
        fsid = uuid.UUID(arg)
    if opt == '-o':
        output = arg
        

text_bpf = text_bpf.replace("##FUNC_NAME##", target_func)
b = BPF(text = text_bpf)

if output:
    fd = open(output, mode="w")
b["events"].open_perf_buffer(process_event, page_cnt=64)
stack_traces = b.get_table("stack_traces")
print("start recording", file=stderr)
while 1:
    try:
        b.perf_buffer_poll()
    except:
        print()
        print_fs_dict()
        exit(0)

