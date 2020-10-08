#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# execsnoop Trace new processes via exec() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# usage: execsnoop.py [-h] [-T] [-t] [-x] [--kprobe] [--cgroupmap CGROUPMAP]
#                     [--mntnsmap MNTNSMAP] [-u USER] [-q] [-n NAME] [-l LINE]
#                     [-U] [--max-args MAX_ARGS] [--arg-pages ARG_PAGES]
#
# The tracepoint version of this tool can copy up to ARG_PAGES*4096 bytes of
# arguments out of the kernel.
# The --max-args option can still used to limit what is displayed in the output
#
# The kprobe version will print up to a maximum of 19 arguments, plus the
# process name, so 20 fields in total (MAXARG).
#
# This won't catch all new processes: an application may fork() but not exec().
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.
# 23-Sep 2020   Nabil Schear    Updated use to sched_process_exec tracepoint.

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import argparse
import re
import time
import pwd
from time import strftime
import ctypes as ct
import math
import os

def parse_uid(user):
    try:
        result = int(user)
    except ValueError:
        try:
            user_info = pwd.getpwnam(user)
        except KeyError:
            raise argparse.ArgumentTypeError(
                "{0!r} is not valid UID or user entry".format(user))
        else:
            return user_info.pw_uid
    else:
        # Maybe validate if UID < 0 ?
        return result


# arguments
examples = """examples:
    ./execsnoop           # trace all exec() syscalls
    ./execsnoop -T        # include time (HH:MM:SS)
    ./execsnoop -U        # include UID
    ./execsnoop -u 1000   # only trace UID 1000
    ./execsnoop -u root   # get user UID and trace only this
    ./execsnoop -t        # include timestamps
    ./execsnoop -q        # add "quotemarks" around arguments
    ./execsnoop -n main   # only print command lines containing "main"
    ./execsnoop -l tpkg   # only print command where arguments contains "tpkg"
    ./execsnoop -x --kprobe          # include failed exec()s (requires kprobe)
    ./execsnoop --cgroupmap mappath  # only trace cgroups in this BPF map
    ./execsnoop --mntnsmap mappath   # only trace mount namespaces in the map
    ./execsnoop --arg-pages 512      # allocate 2MB for arguments of each exec
"""
parser = argparse.ArgumentParser(
    description="Trace exec() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--time", action="store_true",
    help="include time column on output (HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-x", "--fails", action="store_true",
    help="include failed exec()s")
parser.add_argument("--kprobe", action="store_true",
    help="force use of less reliable kprobe instrumentation")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-u", "--uid", type=parse_uid, metavar='USER',
    help="trace this UID only")
parser.add_argument("-q", "--quote", action="store_true",
    help="Add quotemarks (\") around arguments.")
parser.add_argument("-n", "--name", type=ArgString,
    help="only print commands matching this name (regex), any arg")
parser.add_argument("-l", "--line", type=ArgString,
    help="only print commands where arg contains this line (regex)")
parser.add_argument("-U", "--print-uid", action="store_true",
    help="print UID column")
parser.add_argument("--max-args", default="20",
    help="number of args parsed and displayed, defaults to 20")
parser.add_argument("--arg-pages", default="1",
    help="number of 4K pages to allocate for args, default 1, max 512")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# This program uses a raw tracepoint on sched_process_exec to trace executions.
# There are several benefits of tracing executions in this way instead of using
# a kprobe on the execve syscall.
#  - arguments are fully present in kernel memory (not paged out and subject
#    to TOCTOU vulnerabilities).
#  - arguments are aligned in the memory of the exec'd process, so we can copy
#    them in bulk and process them in userspace.  This avoids the 255 byte
#    individual arg limit that the kprobe version uses.  We can collect up to
#    the kernel's maximum of 2MB of arguments.
#  - the struct file of the actual binary being executed is available so we
#    know conclusively what's being executed.
#  - this tracepoint exists at the same location in kernel code where the audit
#    subsystem logs executions, so it's suitable for security auditing.
#
#  one negative side effect of using this tracepoint is that the tool cannot
#  report on failed execs.  Use the --kprobe option to track failed execs.
#
bpf_text_raw_tracepoint = """
    #include <linux/binfmts.h>
    #include <linux/fs.h>
    #include <linux/mount.h>
    #include <linux/sched.h>

    BPF_ARRAY(errors,u64,4);
    #define ERR_PATH_OVER 0
    #define ERR_PATH_READ 1
    #define ERR_ARG_READ 2

    #define FULL_PATH_SIZE 4096
    #define MAX_PATH_ENTRIES %MAX_PATH_ENTRIES%
    #define PATH_ENTRY_SIZE %PATH_ENTRY_SIZE%

    // set args size in pages
    // -40 accounts for the other fields of the struct (pid, args_count, etc.)
    #define FULL_ARG_SIZE (%NUM_ARG_PAGES%*4096-40)

    // an event to store the exec metadata
    struct event {
        u32 pid;
        u32 tgid;
        u32 ppid;
        u32 uid;
        s32 args_count;
        u32 args_size;
        s32 path_count;
        u32 path_size;
        u64 i_ino;
        u8 path[FULL_PATH_SIZE];
        u8 args[FULL_ARG_SIZE];
    };

    #define BASE_EVENT_SIZE (size_t)(&((struct event*)0)->args)
    #define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)

    // declare output buffer
    BPF_PERF_OUTPUT(events);

    // single element per-cpu array to hold the current event off the stack
    BPF_PERCPU_ARRAY(event_array,struct event,1);

    int trace_sched_process_exec(struct bpf_raw_tracepoint_args *ctx) {
        u64 id;
        pid_t pid, tgid;
        unsigned int ret;
        struct event *event;
        struct task_struct *task;
        u32 eventkey = 0;
        s32 i;

        u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

        UID_FILTER

        if (container_should_be_filtered()) {
            return 0;
        }

        id = bpf_get_current_pid_tgid();
        pid = (pid_t)id;
        tgid = id >> 32;

        event = event_array.lookup(&eventkey);
        if (!event) // this should never happen, just making the verifier happy
            return 0;

        event->pid = pid;
        event->tgid = tgid;
        event->uid = uid;
        task =  (struct task_struct *)ctx->args[0];
        event->ppid = (pid_t)task->real_parent->tgid;

        // get the pointer to the bprm structure
        // to get the arg count and file struct
        struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

        // grab the inode just in case there's a problem getting the path
        event->i_ino = bprm->file->f_inode->i_ino;

        // argument count
        event->args_count = bprm->argc;

        // get the path from the file struct
        // switch once bpf_d_path is available for raw_tracepoints
        // https://bit.ly/33fro5b
        struct dentry *dentry = bprm->file->f_path.dentry;

        u8 clean=0;
        event->path_size=0;
        event->path_count = 0;
        for (i = 0 ; i < MAX_PATH_ENTRIES; i++) {
            if( event->path_size > FULL_ARG_SIZE-PATH_ENTRY_SIZE) {
                errors.increment(ERR_PATH_OVER);
                break;
            }
            ret = bpf_probe_read_str(&event->path[event->path_size],
                                     PATH_ENTRY_SIZE, dentry->d_name.name);
            if (ret > PATH_ENTRY_SIZE) {
                errors.increment(ERR_PATH_READ);
            } else {
                event->path_size += ret;
            }
            event->path_count++;

            // root directory is its own parent
            if (dentry == dentry->d_parent) {
                clean=1;
                break;
            }

            //iterate up the chain
            dentry = dentry->d_parent;
        }

        if(clean==0) {
            // mark the path len as negative to indicate overflow
            event->path_count *= -1;
        }

        event->args_size = task->mm->arg_end-task->mm->arg_start;
        // bounds check bytes copied
        u32 read_size = 0;
        if (event->args_size > FULL_ARG_SIZE)
            read_size = FULL_ARG_SIZE;
        else
            read_size = event->args_size;

        // need to explicitly read this to cause bpf_probe_read automatically
        const char *arg_start = (const char*)task->mm->arg_start;

        ret = bpf_probe_read(event->args, read_size, arg_start);
        if (ret != 0)
            errors.increment(ERR_ARG_READ);

        // submit the event
        size_t len = EVENT_SIZE(event);
        if (len <= sizeof(*event))
            events.perf_submit(ctx, event, len);

        return 0;
    }
"""

# This program uses a kprobe/kretprobe on the execve syscall to trace execs.
# It uses a very similar design to the program used by the execsnoop in the
# C-based libbpf-tools.
#
# It will copy up to MAX_ARGS (up to 60) of ARG_LENGTH (128 bytes) to
# userspace.  (including the first argument, the executed binary)
#
# This version of tracing is less reliable than using the raw tracepoint (see
# comment above).  We recommend using the kprobe version only if you need to
# trace failed execs or if the raw tracepoint is not available in your kernel.
#
bpf_text_kprobe = """
    #include <linux/fs.h>
    #include <linux/mount.h>
    #include <linux/sched.h>

    BPF_ARRAY(errors,u64,4);
    #define ERR_ARG_READ 2
    #define ERR_ARG_OVER 3

    #define ARGSIZE %ARGSIZE%
    #define MAXARGS %MAXARGS%
    #define TOTAL_MAX_ARGS %TOTAL_MAX_ARGS%
    #define TASK_COMM_LEN 16
    #define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
    #define BASE_EVENT_SIZE (size_t)(&((struct event*)0)->args)
    #define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
    #define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

    // an event to store the exec metadata
    struct event {
        u32 pid;
        u32 tgid;
        u32 ppid;
        u32 uid;
        s32 args_count;
        u32 args_size;
        u8 args[FULL_MAX_ARGS_ARR];
    };

    // declare output buffer
    BPF_PERF_OUTPUT(events);

    // single element per-cpu array to hold the current event off the stack
    BPF_PERCPU_ARRAY(event_array,struct event,1);

    // an event to store the exec metadata
    struct retevent {
        u32 pid;
        s32 retval;
    };
    // declare output buffer for returns
    BPF_PERF_OUTPUT(retevents);


    int syscall__execve(struct pt_regs *ctx,
        const char __user *filename,
        const char __user *const __user *__argv,
        const char __user *const __user *__envp)
    {
        u64 id;
        pid_t pid, tgid;
        unsigned int ret;
        struct event *event;
        struct task_struct *task;
        const char *const *args = __argv;
        const char *argp;
        uid_t uid = (u32)bpf_get_current_uid_gid();
        int eventkey=0;

        UID_FILTER

        if (container_should_be_filtered()) {
            return 0;
        }

        id = bpf_get_current_pid_tgid();
        pid = (pid_t)id;
        tgid = id >> 32;

        event = event_array.lookup(&eventkey);
        if (!event) // this should never happen, just making the verifier happy
            return 0;

        event->pid = pid;
        event->tgid = tgid;
        event->uid = uid;
        task = (struct task_struct*)bpf_get_current_task();
        event->ppid = (pid_t)task->real_parent->tgid;
        event->args_count = 0;
        event->args_size = 0;

        ret = bpf_probe_read_str(event->args, ARGSIZE, filename);
        if (ret <= ARGSIZE) {
            event->args_size += ret;
        } else {
            errors.increment(ERR_ARG_READ);
            // write an empty string
            event->args[0] = 0;
            event->args_size++;
        }

        event->args_count++;
        int i=1;
        #pragma unroll
        for (i = 1; i < TOTAL_MAX_ARGS; i++) {
            bpf_probe_read(&argp, sizeof(argp), &args[i]);
            if (!argp)
                break;

            if (event->args_size > LAST_ARG) {
                errors.increment(ERR_ARG_OVER);
                break;
            }

            ret = bpf_probe_read_str(&event->args[event->args_size], ARGSIZE,
                                     argp);
            if (ret > ARGSIZE) {
                errors.increment(ERR_ARG_READ);
                break;
            }

            event->args_count++;
            event->args_size += ret;
        }
        if (i == TOTAL_MAX_ARGS) {
            // try to read one more argument to check if there is one
            bpf_probe_read(&argp, sizeof(argp), &args[TOTAL_MAX_ARGS]);
            // pointer to max_args+1 isn't null, assume we have more arguments
            if (argp)
                event->args_count++;
        }

        // submit the event
        size_t len = EVENT_SIZE(event);
        if (len <= sizeof(*event))
            events.perf_submit(ctx, event, len);

        return 0;
    }

    int do_ret_sys_execve(struct pt_regs *ctx)
        {
        u64 id;
        pid_t pid;
        struct retevent retevent;

        u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

        UID_FILTER

        if (container_should_be_filtered()) {
            return 0;
        }

        id = bpf_get_current_pid_tgid();
        pid = (pid_t)id;

        retevent.pid = pid;
        retevent.retval = PT_REGS_RC(ctx);

        // submit the event
        retevents.perf_submit(ctx, &retevent, sizeof(retevent));
        return 0;
    }
"""

if os.geteuid() != 0:
    print("Error: this program must be run as root")
    exit(-1)

# how many exec events should fit in the output perfbuffer
PERFBUFFER_EVENTS = 64

# max args displayed
MAX_DISPLAY_ARGS = 100

try:
    args.max_args = int(args.max_args)
    if args.max_args > MAX_DISPLAY_ARGS or args.max_args < 1:
        args.max_args = None
except BaseException:
    args.max_args = None
if args.max_args is None:
    print("Error: invalid max args %s. Please specify a number between 1 "
          "and %s" % MAX_DISPLAY_ARGS)
    exit(-1)

if args.kprobe:
    # kprobe constants
    ARG_SIZE = 128
    TOTAL_MAX_ARGS = 60

    if args.max_args > TOTAL_MAX_ARGS:
        print("Error: invalid max args %s. Please specify a number between 1 "
              "and %s" % TOTAL_MAX_ARGS)
        exit(-1)

    bpf_text = bpf_text_kprobe
    tracepoint = False

    bpf_text = bpf_text.replace("%ARGSIZE%", str(ARG_SIZE))
    bpf_text = bpf_text.replace("%TOTAL_MAX_ARGS%", str(TOTAL_MAX_ARGS))
    bpf_text = bpf_text.replace("%MAXARGS%", str(args.max_args))

    # size of struct event is a little less than 2 pages
    PAGES = 2 * PERFBUFFER_EVENTS

    # store exec events to correlate with return events
    stored_events = {}
else:
    # tracepoint constants
    PATH_ENTRY_SIZE = 255
    MAX_PATH_ENTRIES = 100

    # 2MB is the max args size in the kernel
    MAX_PAGES = 512

    if not BPF.tracepoint_exists("sched", "sched_process_exec") or \
            not BPF.support_raw_tracepoint():
        print("Error: The sched_process_exec raw tracepoint is NOT available "
              "on your system.\n\tUse --kprobe instead.")
        exit(-1)

    bpf_text = bpf_text_raw_tracepoint
    tracepoint = True
    try:
        args.arg_pages = int(args.arg_pages)
        if args.arg_pages > MAX_PAGES or args.arg_pages < 1:
            args.arg_pages = None
    except BaseException:
        args.arg_pages = None
    if args.arg_pages is None:
        print("Error: invalid max arg pages %s. Please specify a number "
              "between 1 and %s" % MAX_PAGES)
        exit(-1)

    # ensure there's enough room for PERFBUFFER_EVENTS
    PAGES = int(PERFBUFFER_EVENTS * 2 ** math.ceil(math.log(float(
        args.arg_pages) + 1.0, 2)))

    bpf_text = bpf_text.replace("%NUM_ARG_PAGES%", str(args.arg_pages))
    bpf_text = bpf_text.replace("%PATH_ENTRY_SIZE%", str(PATH_ENTRY_SIZE))
    bpf_text = bpf_text.replace("%MAX_PATH_ENTRIES%", str(MAX_PATH_ENTRIES))

if args.fails and tracepoint:
    print("Error: The sched_process_exec tracepoint is available on your"
        " system, but it cannot report failed execs.\n\tTo see failed execs"
        " use the --kprobe option to use the less reliable kprobe method of"
        " tracing execs.")
    exit(-1)

if args.uid is not None:
    bpf_text = bpf_text.replace('UID_FILTER',
                                'if (uid != %s) { return 0; }' % args.uid)
else:
    bpf_text = bpf_text.replace('UID_FILTER', '')
bpf_text = filter_by_containers(args) + bpf_text
if args.ebpf:
    print(bpf_text)
    exit(0)

# initialize BPF
b = BPF(text=bpf_text)
if tracepoint:
    pass
    b.attach_raw_tracepoint(
        tp="sched_process_exec",
        fn_name="trace_sched_process_exec")
else:
    execve_fnname = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
    b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

# header
if args.time:
    print("%-9s" % ("TIME"), end="")
if args.timestamp:
    print("%-8s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-16s %-6s %-6s %3s %s" % ("PCOMM", "PID", "PPID", "RET", "ARGS"))

# Explicitly define this structure to avoid confusion with exec events
class Retevent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("retval", ct.c_int32),
    ]


# error column labels and indices for how the bpf programs report errors
err_cols = {
    # ERR_PATH_OVER
    "File path too large for buffer. Refer to inode for location.": 0,
    # ERR_PATH_READ
    "Unable to read file path entry. Refer to inode for location.": 1,
    # ERR_ARG_READ
    "Unable to read arg(s). Increase --arg-pages or --max-args.": 2,
    # ERR_ARG_OVER
    "Arg(s) too large for buffer. Increase --max-args.": 3,
}

# hold counts of previously seen errors, initialize to 0
err_count = [0] * 4

# notify of errors in the bpf program
def print_errors():
    errors = b["errors"]
    for k in err_cols:
        err_val = errors[ct.c_int(err_cols[k])].value
        if err_val > err_count[err_cols[k]]:
            err_count[err_cols[k]] += 1
            print("Error: %s err_cnt: %d" % (k, err_val))


# This is best-effort PPID matching. Short-lived processes may exit
# before we get a chance to read the PPID.
# This is a fallback for when fetching the PPID from task->real_parent->tgip
# returns 0, which happens in some kernel versions.
def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0

# process execve return event (kprobe only)
def print_retevent(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Retevent)).contents

    if (event.retval != 0 and not args.fails) or stored_events.get(
            event.pid, None) is None:
        # don't print failed execs or execs that would have been skipped
        return
    event_str, argv_text = stored_events[event.pid]
    event_str += b" %3d %s" % (event.retval, argv_text)
    printb(event_str)
    return

# process exec event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    skip = False

    print_errors()

    if tracepoint:
        pathv = []
        last = 0
        any_trunc = False
        for i in range(event.path_size):
            if event.path[i] == 0:
                curpath = bytearray(event.path[last:i])
                if len(curpath) == PATH_ENTRY_SIZE - 1:
                    any_trunc = True
                    curpath = b"%s...(truncated)" % curpath
                pathv.append(curpath)
                last = i + 1

        pathv = list(map(bytes, pathv))

        if event.path_count < 0:
            any_trunc = True
            pathv.append(b".../")

        if any_trunc:
            pathv[0] = pathv[0] + b"(inode %d)" % event.i_ino

        # truncate to 16 chars for comm.  full name will be shown in argv
        comm = pathv[0]
        if len(comm) > 16:
            comm = comm[:16]

        pathv.reverse()
        path = pathv[0] + b'/'.join(pathv[1:])

    argv = []
    last = 0
    for i in range(event.args_size):
        if event.args[i] == 0:
            argv.append(bytearray(event.args[last:i]))
            last = i + 1
    argv = list(map(bytes, argv))
    if len(argv) < event.args_count:
        argv.append(b"...(%d args not copied)" %
                    (event.args_count - len(argv)))

    max_display_args = args.max_args
    oldlen = len(argv)
    if oldlen > max_display_args:
        argv = argv[:max_display_args]
        argv.append(b"...(%d args not shown)" % (oldlen - max_display_args))

    if tracepoint:
        # replace the first arg with the path we got from the d_entry
        argv[0] = path
    else:
        comm = argv[0].split(b'/')[-1]
        if len(comm) > 16:
            comm = comm[:16]

    if args.name and not re.search(bytes(args.name), comm):
        skip = True
    if args.line and not re.search(
        bytes(args.line), b' '.join(argv)):
        skip = True

    if args.quote:
        argv = [
            b"\"" + arg.replace(b"\"", b"\\\"") + b"\""
            for arg in argv
        ]

    if not skip:
        event_str = b""
        if args.time:
            event_str += b"%-9s" % strftime("%H:%M:%S").encode('ascii')
        if args.timestamp:
            event_str += b"%-8.3f" % (time.time() - start_ts)
        if args.print_uid:
            event_str += b"%-6d" % event.uid
        ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
        ppid = b"%d" % ppid if ppid > 0 else b"?"
        argv_text = b' '.join(argv).replace(b'\n', b'\\n')
        event_str += b"%-16s %-6d %-6s" % (comm, event.pid, ppid)

        if not tracepoint:
            stored_events[event.pid] = (event_str, argv_text)
        else:
            # return value is always 0 for tracepoint probe
            event_str += b" %3d %s" % (0, argv_text)
            printb(event_str)
    else:
        stored_events[event.pid] = None


def lost(count):
    print("WARNING: BPF output buffer overflow. %d exec events dropped!"
          % count)


start_ts = time.time()

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, PAGES, lost)

if not tracepoint:
    b["retevents"].open_perf_buffer(print_retevent, 1, lost)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
