#ifndef __SYSCALL_H
#define __SYSCALL_H

struct execve_args{
    __u64 unused;
    __u64 unused2;
    char *filename;
};

struct event{
    int pid;
    u8 filename[512];
};

#endif
