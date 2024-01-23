#include "vmlinux.h"
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include "syscall.h"

struct event _event = {0};

struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int execve_called(struct execve_args *params)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct event *evt = bpf_ringbuf_reserve(&ringbuf, sizeof(struct event), 0);
    if (!evt)
        {
            bpf_printk("%s\n", "ringbuf_reserve failed");
            return 1;
        }
    evt->pid = pid;
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), params->filename);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}


char LICENSE[] SEC("license") = "GPL";
int VERSION SEC("version") = LINUX_VERSION_CODE;
