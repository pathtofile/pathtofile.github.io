---
layout: post
title:  "Detecting Kernel Hooking using eBPF"
date:   2021-07-07 12:00:00 +0000
cat:    eBPF
---

## tl;dr
I demonstrate [an example project](https://github.com/pathtofile/bpf-hookdetect) that uses eBPF and stack traces
to detect syscall-hooking kernel rootkits. Maybe?


## Rootkits and hooking
A common technique of Linux kernel rootkits is to overwrite the function addresses in the syscall table.
Syscalls are the main way usermode programs interact with the kernel and underlying hardware,
so by altering (or 'hooking') the syscall table, rootkits can change the data reported
by the kernel to hide anything incriminating, such as a network connection to a command and control server,
or a running malware process.

![Diagram showing a rootkit hooking the sys_read syscall](/assets/hooking.png)

On older kernels, hooking the syscall table was as simple as:
```c++
// Module entry
static int __init rootkit_init(void) {
    // Lookup syscall table
    static unsigned long *syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    
    // Overwrite function address in table
    __sys_call_table[__NR_kill] = (unsigned long)hacked_kill;
    return 0;
}

// Hooked kill syscall
int hacked_kill(pid_t pid, int sig) {
    // Do things with input

    // Can also call real function
    int ret = original_kill(pid, sig);

    // Do things with output
    return ret;
}
```

Newer kernels make it [slightly more difficult](https://xcellerator.github.io/posts/linux_rootkits_11), but it is still a very common technique.
By replacing the main entrypoint to various syscalls, Kernel rootkits have control over what gets sent to and from
the kernel, and can decide whether to even call the original syscall function.

[Diamorphine](https://github.com/m0nad/Diamorphine) a great example of a Linux Kernel rootkit, and being open source
we can [clearly see](https://github.com/m0nad/Diamorphine/blob/master/diamorphine.c#L413) that it hooks three syscalls:

#### Kill
Kill is used to send signals between processes. Diamorphine uses this as the main command-and-control:
- Sending signal `31` to a process will hide a process
- Sending signal `63` to any process will hide or unhide the kernel module
- Sending signal `64` to any process will elevate the caller process to root

By hooking the `kill` syscall, Diamorphine first checks if the signal is one of these magic numbers. If it's not
it will pass the signal to the read `sys_kill` function, otherwise, it will instead do one of its special actions.


#### Getdents/Getdents64
These syscalls are used by functions to list the contents of directories. Diamorphine will call the read syscall function, then check
the return data to remove any files or folders it wants to hide from the user.

This is also how it hides processes: Tools like `ps` list processes by looking in the `/proc/` folder, as each process has a pseudo-folder there that contains the details about the process' PID, commandline, etc. By hiding a process's folder in `/proc/` you also hide it from `ps` and other tools.


## Reading Stacks with eBPF
One of the coolest lesser-used features of eBPF is the ability to record stack traces of a function call, showing what functions were called in both userspace and the kernel, leading up to the function eBPF is attached to.

This is great for debugging, but also super useful to detect when a function or syscall has been hooked: if we know what functions should be in the stage trace without being hooked, we can tell when the hooked function has inserted itself into the chain.

To test this, I first created a simple eBPF Program to record the stack trace from all `kill` syscalls:
```c++
// Stack traces get stored in a special eBPF Map
#define MAX_STACK_DEPTH 10
struct bpf_map_def SEC("maps") map_stack_traces = {
  .type = BPF_MAP_TYPE_STACK_TRACE,
  .key_size = sizeof(u32),
  .value_size = sizeof(size_t) * MAX_STACK_DEPTH,
  .max_entries = 8192,
};

// Use a ringbuffer Map to send data down to userspace
struct bpf_map_def SEC("maps") rb = {
  .type = BPF_MAP_TYPE_RINGBUF,
  .max_entries = 256 * 1024,
};

// Define the format of the event to send to userspace
struct event {
    unsigned long stack_id;
};


// Attatch a KProbe to the kill syscall function
// which on x64 is '__x64_sys_kill'
SEC("kprobe/__x64_sys_kill")
int BPF_PROG(sys_kill, const struct pt_regs *regs)
{
    // Call bpf helper function to store the stack trace in the map
    long stack_id = bpf_get_stackid(ctx, &map_stack_traces, 0);

    // Log event to ringbuffer to be read by userspace
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->stack_id = stack_id;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}
```

Then I used the [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap/) code as a template, but changed the `handle_event` function:
```c++
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    // Stack addresses are 64bit unsigned ints
    u64 stacks[MAX_STACK_DEPTH] = { 0 };
    u64 stack = 0;

    // Same event struct definition as bPF code
    const struct event *e = data;

    // Lookup stack id in map_stack_traces
    int ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.map_stack_traces), &e->stack_id, &stacks);
    if (ret < 0) {
        printf("Error finding stack trace\n");
        return 0;
    }

    // Loop through stack and print each address
    printf("Kill stack Trace:\n");
    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
        stack = stacks[stack_i];
        // Once we get to NULLs, we've walked the whole stacktrace
        if (stack == 0) {
            break;
        }
        printf("    0x%llx\n", stack);
    }
    return 0;
}
```

When I ran this program on an `Ubuntu 21.04 (kernel 5.11.0)` machine, I got this output:
```bash
## Terminal 1 - send arbitrary signal 23 to own process
kill -s 23 $$

## Terminal 2 - eBPF Logging
Starting...
Kill stack Trace:
    0xffffffff886b88e1
    0xffffffff8940008c
Stopping...
```

So on this machine, there are only 2 stack frames. To find out what functions these addresses corespond to, you can look in the psudo-file `/proc/kallsyms`. As the stack addresses are unlikley to be at the start of a function, you need to look for the closest address that occurs *before* your target address. This still might not be accurate as the stack could have come from a non-public function (which would not be visible in `kallsyms`), but it's a good test, and doesn't require you to re-compile the kernel with full debug symbols. 

In my case, the addresses corresponded to:
```bash
0xffffffff886b88e1 -> __x64_sys_kill (started at 0xffffffff886b88dc)
0xffffffff8940008c -> entry_SYSCALL_64_after_hwframe (started at 0xffffffff89400048)
```

This all lined up with my understanding - The last stack frame is the syscall function, and the first is possibly the main syscall entry function after the hardware interrupt.

Next, I installed the Diamorphine rootkit and re-ran the eBPF Program. This time I got a different output:
```bash
## Terminal 1 - send arbitrary signal 23 to own process
kill -s 23 $$

## Terminal 2 - eBPF Logging
Starting...
Kill stack Trace:
    0xffffffff9d8b8991 # __x64_sys_kill
    0xffffffff9e436ab8 # ?!
    0xffffffff9e60008c # entry_SYSCALL_64_after_hwframe
Stopping...
```

I could now see a third stack frame in between the expected two. Looking in `/proc/kallsyms`, the address appears to be in `do_syscall_64`, but that's not quite right.
I'm not sure why the address inside `do_syscall_64` is listed, instead of the Diamorphine function [hacked_kill](https://github.com/m0nad/Diamorphine/blob/master/diamorphine.c#L313), which on this machine was at `0xffffffffc0962000`.
This is something I plan to follow up on once I understand more about how `bpf_get_stackid` actually works.

However, even if the address wasn't correct, I could still tell that the syscall had been hooked, as a new stack frame was inserted in between the two expected frames.


## Finding the missing call
This works when the real function is called, but what happens when you run `kill -s 63`, which is one of the special Diamorphine signals that doesn't get forwarded to the real syscall?
```bash
## Terminal 1 - send special signal 64 to pid 0 (which unhides the rootkit)
kill -s 63 0

## Terminal 2 - eBPF Logging
Starting...
Stopping...
```

As the real syscall function is never called, neither is our BPF code. One way to detect when this occurs is to
run two more eBPF Programs, attached to `raw_tracepoint/sys_enter` and `raw_tracepoint/sys_exit`. These
are always run before the syscall table is looked up, and should be run irregardless of if the real syscall function
is run or not. This means you can:
1. Attach eBPF to `raw_tracepoint/sys_enter`, and if the thread is about to call `sys_kill`, record the thread ID
2. Attach eBPF to `__x64_sys_kill`, record that the thread did actually call the function, along with the call stack
3. Attach eBPF to `raw_tracepoint/sys_exit`, check if the thread was meant to have called`sys_kill`. If it was meant to but the program attached to `__x64_sys_kill` didn't see it, raise an alert.

By combining the `stack length` and `raw_tracepoints` checks, you have have a decently reliable way to detect when rootkits like Diamorphine are being used.

## BPF-Hookdetect
I've combined these techniques into a simple project I've called [BPF-HookDetect](https://github.com/pathtofile/bpf-hookdetect):
```bash
sudo ./bpf-hookdetect/src/bin/hookdetect --verbose
## In another teminal: 'ps'
sys_getdents64:
    0xffffffff9db397f1 -> __x64_sys_getdents64
    0xffffffff9e436ab8 -> do_syscall_64
    0xffffffff9e60008c -> entry_SYSCALL_64_after_hwframe
sys_getdents64 is hooked for PID 14145 (ps) - Real function called but data possibly altered
## In another teminal: 'kill -s 23 $$'
sys_kill:
    0xffffffff9d8b8991 -> __x64_sys_kill
    0xffffffff9e436ab8 -> do_syscall_64
    0xffffffff9e60008c -> entry_SYSCALL_64_after_hwframe
sys_kill is hooked for PID 7112 (bash) - Real function called but data possibly altered
## In another teminal: 'kill -s 63 0'
sys_kill is hooked for PID 7112 (bash) - Real function not called
```

## Limitations
Hookdetect is only meant to demonstrate the idea of using stack traces to detect dodginess. But it comes with several limitations,
that could make it challenging or impossible to implement in a production environment:

#### Performance Impact
Intercepting and analysing every syscall on the machine would almost certainly have performance impacts on real/production systems.
This could be improved a bit by only looking for specific syscalls, or only running for a short period of time.

#### Not only syscalls get hooked
Some rootkits such as [Reptile](https://github.com/f0rb1dd3n/Reptile) don't hook the syscall functions. Instead, they hook other functions inside the kernel such as [vfs_read](https://github.com/f0rb1dd3n/Reptile/blob/1e17bc82ea8e4f9b4eaf15619ed6bcd283ad0e17/kernel/main.c#L221).

These functions may be called legitimately from many different places inside the kernel, and even legitimately by other kernel modules,
so more work would be needed to determine a normal stack trace from a hooked one.


## Conclusion
The goal of this blog was to explore one way eBPF could be used to detect kernel rootkits, as well as demonstrate how to use `bpf_get_stackid` to lookup stack traces.
The code and more references are available [on GitHub](https://github.com/pathtofile/bpf-hookdetect).

Apologies if this blog was a bit more disjointed than usual, it was written over the course of the month as our family dealt with lockdowns, sickness, and daycare.
