Btrfs-profilers
===============

Btrfs-profilers is a collection of BCC(https://github.com/iovisor/bcc) based
btrfs performance analyse tools.

License: GPLv2

This repository hosts following utilities:
* **tree_lock_wait.py** &mdash; real time tree block locking wait time profiler

Prerequisite
------------
The following packages are required to use above tools:

* kernel-headers -- to compile kernel modules used by bcc/eBPF
* bcc
* bcc-python2
* bcc-python3

In general, to use these features, a Linux kernel version 4.1 or newer is
required. In addition, the kernel should have been compiled with the following
flags set:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
# [optional, for tc filters]
CONFIG_NET_CLS_BPF=m
# [optional, for tc actions]
CONFIG_NET_ACT_BPF=m
CONFIG_BPF_JIT=y
# [for Linux kernel versions 4.1 through 4.6]
CONFIG_HAVE_BPF_JIT=y
# [for Linux kernel versions 4.7 and later]
CONFIG_HAVE_EBPF_JIT=y
# [optional, for kprobes]
CONFIG_BPF_EVENTS=y
```

There are a few optional kernel flags needed for running bcc networking examples on vanilla kernel:

```
CONFIG_NET_SCH_SFQ=m
CONFIG_NET_ACT_POLICE=m
CONFIG_NET_ACT_GACT=m
CONFIG_DUMMY=m
CONFIG_VXLAN=m
```

Also refer to bcc projects for [installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
