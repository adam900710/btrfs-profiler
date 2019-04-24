#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# This program generates a BPF program to inject error to specified functions
# for error path testing.
#
# Ther are mainly several parts involved in such use case:
#   function1()
#   |- function2()
#      |- function3()
#         |- inject_target()
#
#   inject_target() is the function we're going to inject error into
#   It can either be:
#   - presets from bcc/tools/inject "kmalloc"|"bio"|"alloc_page"
#     the same as inject.py in bcc.
#     this tool will complete the parameter list.
#
#   - custom function:
#     needs function name along with its parameter list
#     e.g "btrfs_check_tree_leaf(struct extent_buffer *eb):-EUCLEAN"
#     parameter list is used for kprobe to do extra filter (see below), can be
#     empty if not used.
#     the return value is also needed for error override.
#
#   function1/2/3() are optional, it's designed to only inject error
#   for certain call chain.
#
#   The final part is the extra filter in the injected function.
#   E.g, to inject error for kmalloc() we override the return value of
#        should_failslab(), but we may not want to fail allocation request
#        with __GFP_NOFAIL flag. Then we can use the extra filter
#        "!(gfpflags & __GFP_NOFAIL)".
#
# NOTE: This tool requires CONFIG_BPF_KPROBE_OVERRIDE
#
# Usage:
#   inject.py [-h] [-I extra_global_header] \
#             [-P probability] [-v] [-F extra_filter]
#             [-C functions in callchain] target
#
# Examples:
# # inject.py -C "extent_writepages():submit_one_bio():" -P 0.01 \
#             -F "!(gfpflags & __GFP_NOFAIL)" kmalloc
# This will cause any kmalloc() call to fail under
# extent_writepages()->submit_one_bio() at 1% rate, and only fail for kmalloc()
# call without __GFP_NOFAIL flag.
#
# # inject.py -C "csum_dirty_buffer()" -P 0.001 \
# "btrfs_check_leaf_full(struct btrfs_fs_info *fs_info, struct extent_buffer *eb):-EUCLEAN"
# This will cause random write tree checker to fail.

import getopt 
import re
from bcc import BPF
from sys import argv
from sys import stderr
from sys import exit

c_src = '''
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
##EXTRA_HEADERS##

#define STACK_DEPTH     ##STACK_DEPTH##

struct pid_struct {
    /* Counters for parent functions hitted, don't handle recursive calls yet */
    u64 stack_count;
};

BPF_HASH(m, u64, struct pid_struct);

int target_entry(struct pt_regs *ctx ##PARAMETERS##)
{
    int ret;
    u64 pid = bpf_get_current_pid_tgid();
    struct pid_struct *p;

    if (!(##EXTRA_FILTER##)) {
        return 0;
    }
    if (STACK_DEPTH) {
        p = m.lookup(&pid);
        if (!p) {
            return 0;
        }
        /* recursive can be triggered multiple times */
        if (p->stack_count < STACK_DEPTH) {
            return 0;
        }
    }
    /*
     * Probability should only affect the function meets all prerequisite.
     * Early exit would make the probability unreliable.
     */
    if (bpf_get_prandom_u32() > ##PROBABILITY##) {
        return 0;
    }
    ret = bpf_override_return(ctx, ##RETURN_VALUE##);
    return ret;
}

int top_entry(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    struct pid_struct p_struct = {0};
    struct pid_struct *p;

    p_struct.stack_count++;
    m.insert(&pid, &p_struct);

    return 0;
}

int top_return(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    struct pid_struct *p;

    p = m.lookup(&pid);
    if (!p)
        return 0;
    if (p->stack_count > 1)
        p->stack_count--;
    else
        m.delete(&pid);
    return 0;
}

int intermediate_entry(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    struct pid_struct *p;

    p = m.lookup(&pid);
    if (!p)
       return 0;
    p->stack_count++;
    return 0;
}

int intermediate_exit(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    struct pid_struct *p;

    p = m.lookup(&pid);
    if (!p)
       return 0;
    if (p->stack_count)
        p->stack_count--;
    return 0;
}
'''

target_dict = {
    "kmalloc" :
        ("should_failslab", "struct kmem_cache *s, gfp_t gfpflags", "-ENOMEM"),
    "bio" : ("should_fail_bio", "struct bio *bio", "-EIO"),
    "alloc_page" :
        ("should_fail_alloc_page", "gfp_t gfpflags, unsinged int order",
         "true")
}

usage_string='''
Usage: %s \\
     [-vh] [-I <extra_global_header>] [-P <probability>] [-F <extra_filter>] \\
     [-C <callchain>] <target>
<target>:
  The error injection target, needs ALLOW_ERROR_INJECTION() to declare.
  Supports two formats for it:
  - Short preset from bcc/tool/inject.py
    "kmalloc", "bio" or "alloc_page" is supported.
  - Full "<function name>(<parameters>):<return value>" format
    E.g. "btrfs_check_leaf_full(struct extent_buffer *eb):-EUCLEAN"

-I <extra_global_header>:
  Extra global header to be included. E.g "linux/fs.h".
  Can be specified multiple times.

-P <probability>:
  Specify the probability the target function should fail.
  Please note this probability is calculated by:
    <failure hits> / <valid target hits (passes callchain and filter check)>.
  Thus if the callchain reduces the target hits to minimal,
  there is no need to specify this option.
  E.g. "0.01". Default value is 1.0.

-F <extra_filter>:
  Extra filter condition to be checked before injecting error.
  This happens before probability check.
  E.g "!(gfpflags & __GFP_NOFAIL)". Default value is "true".

-C <callchain>:
  Specify the full callchain to match, split by ':'.
  Caller first.
  E.g "btree_submit_bio_hook():btree_csum_one_bio()".
  Default value is empty, thus no callchain requirement.

  NOTE: This doesn't handle recursive call yet.

-v: verbose mode
    show the C source file for debug.

-h: help
    show this help info.
'''

def usage():
    print(usage_string % (argv[0], ), file=stderr)
    exit(1)

def parse_callchain(string):
    return string.replace("()", '').split(":")

def parse_target(string):
    result = {}
    if string in target_dict:
        result["target"] = target_dict[string][0]
        result["parameters"] = target_dict[string][1]
        result["return_value"] = target_dict[string][2]
        return result

    tmp = re.findall("\s*(.*)\s*\(\s*(.*)\s*\):\s*(.*)\s*", string)
    if len(tmp[0]) != 3:
        print(tmp)
        print("bad target string: %s" % (string,), file=stderr)
        usage()
    result["target"] = tmp[0][0]
    result["parameters"] = tmp[0][1]
    result["return_value"] = tmp[0][2]
    return result

def parse_include(extra_headers):
    result = ""
    for i in extra_headers:
        result += "#include <%s>\n" % i
    return result

verbose = False
extra_headers = []
probability = 1.0
callchain_list = []
extra_filter = '1'

try:
    optlist, args = getopt.getopt(argv[1:], "hI:P:vF:C:")
except getopt.GetoptError as err:
    print(str(err))
    usage()
for o, a in optlist:
    if o == "-h":
        usage()
    elif o == "-v":
        verbose = True
    elif o == "-I":
        extra_headers.append(a)
    elif o == "-P":
        probability = float(a)
        if (probability > 1.0):
            print("probability can't be larger than 1.0")
            usage()
    elif o == "-C":
        callchain_list = parse_callchain(a)
    elif o == "-F":
        extra_filter = a
    else:
        assert False, "unhanled option"

if len(args) != 1:
    usage()
target = parse_target(args[0])

# Code replacement
c_src = c_src.replace("##EXTRA_HEADERS##", parse_include(extra_headers))
c_src = c_src.replace("##STACK_DEPTH##", str(len(callchain_list)))
if len(target["parameters"]):
    c_src = c_src.replace("##PARAMETERS##", ", " + target["parameters"])
else:
    c_src = c_src.replace("##PARAMETERS##", '')
c_src = c_src.replace("##RETURN_VALUE##", target["return_value"])
c_src = c_src.replace("##PROBABILITY##", str(int(probability * (1 << 32 - 1))))
c_src = c_src.replace("##EXTRA_FILTER##", extra_filter)

if verbose:
    print(c_src)

bpf = BPF(text=c_src)

for i, func in enumerate(callchain_list):
    if i == 0:
        bpf.attach_kretprobe(event=func, fn_name="top_return")
        bpf.attach_kprobe(event=func, fn_name="top_entry")
    else:
        bpf.attach_kretprobe(event=func, fn_name="intermediate_exit")
        bpf.attach_kprobe(event=func, fn_name="intermediate_entry")
bpf.attach_kprobe(event=target["target"], fn_name="target_entry")

print("Probe all attached")
while True:
    try:
        bpf.perf_buffer_poll()
    except:
        for func in callchain_list:
            bpf.detach_kprobe(func)
            bpf.detach_kretprobe(func)
        bpf.detach_kprobe(target["target"])
        exit(0)
