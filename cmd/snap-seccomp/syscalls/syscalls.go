// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package syscalls

// Generated using arch-syscall-dump test tool from libseccomp tree, git
// revision bf747eb21e428c2b3ead6ebcca27951b681963a0.
var SeccompSyscalls = []string{
	"_llseek",
	"_newselect",
	"_sysctl",
	"accept",
	"accept4",
	"access",
	"acct",
	"add_key",
	"adjtimex",
	"afs_syscall",
	"alarm",
	"arch_prctl",
	"arm_fadvise64_64",
	"arm_sync_file_range",
	"bdflush",
	"bind",
	"bpf",
	"break",
	"breakpoint",
	"brk",
	"cachectl",
	"cacheflush",
	"capget",
	"capset",
	"chdir",
	"chmod",
	"chown",
	"chown32",
	"chroot",
	"clock_adjtime",
	"clock_adjtime64",
	"clock_getres",
	"clock_getres_time64",
	"clock_gettime",
	"clock_gettime64",
	"clock_nanosleep",
	"clock_nanosleep_time64",
	"clock_settime",
	"clock_settime64",
	"clone",
	"clone3",
	"close",
	"connect",
	"copy_file_range",
	"creat",
	"create_module",
	"delete_module",
	"dup",
	"dup2",
	"dup3",
	"epoll_create",
	"epoll_create1",
	"epoll_ctl",
	"epoll_ctl_old",
	"epoll_pwait",
	"epoll_wait",
	"epoll_wait_old",
	"eventfd",
	"eventfd2",
	"execve",
	"execveat",
	"exit",
	"exit_group",
	"faccessat",
	"fadvise64",
	"fadvise64_64",
	"fallocate",
	"fanotify_init",
	"fanotify_mark",
	"fchdir",
	"fchmod",
	"fchmodat",
	"fchown",
	"fchown32",
	"fchownat",
	"fcntl",
	"fcntl64",
	"fdatasync",
	"fgetxattr",
	"finit_module",
	"flistxattr",
	"flock",
	"fork",
	"fremovexattr",
	"fsconfig",
	"fsetxattr",
	"fsmount",
	"fsopen",
	"fspick",
	"fstat",
	"fstat64",
	"fstatat64",
	"fstatfs",
	"fstatfs64",
	"fsync",
	"ftime",
	"ftruncate",
	"ftruncate64",
	"futex",
	"futex_time64",
	"futimesat",
	"get_kernel_syms",
	"get_mempolicy",
	"get_robust_list",
	"get_thread_area",
	"get_tls",
	"getcpu",
	"getcwd",
	"getdents",
	"getdents64",
	"getegid",
	"getegid32",
	"geteuid",
	"geteuid32",
	"getgid",
	"getgid32",
	"getgroups",
	"getgroups32",
	"getitimer",
	"getpeername",
	"getpgid",
	"getpgrp",
	"getpid",
	"getpmsg",
	"getppid",
	"getpriority",
	"getrandom",
	"getresgid",
	"getresgid32",
	"getresuid",
	"getresuid32",
	"getrlimit",
	"getrusage",
	"getsid",
	"getsockname",
	"getsockopt",
	"gettid",
	"gettimeofday",
	"getuid",
	"getuid32",
	"getxattr",
	"gtty",
	"idle",
	"init_module",
	"inotify_add_watch",
	"inotify_init",
	"inotify_init1",
	"inotify_rm_watch",
	"io_cancel",
	"io_destroy",
	"io_getevents",
	"io_pgetevents",
	"io_pgetevents_time64",
	"io_setup",
	"io_submit",
	"io_uring_enter",
	"io_uring_register",
	"io_uring_setup",
	"ioctl",
	"ioperm",
	"iopl",
	"ioprio_get",
	"ioprio_set",
	"ipc",
	"kcmp",
	"kexec_file_load",
	"kexec_load",
	"keyctl",
	"kill",
	"lchown",
	"lchown32",
	"lgetxattr",
	"link",
	"linkat",
	"listen",
	"listxattr",
	"llistxattr",
	"lock",
	"lookup_dcookie",
	"lremovexattr",
	"lseek",
	"lsetxattr",
	"lstat",
	"lstat64",
	"madvise",
	"mbind",
	"membarrier",
	"memfd_create",
	"migrate_pages",
	"mincore",
	"mkdir",
	"mkdirat",
	"mknod",
	"mknodat",
	"mlock",
	"mlock2",
	"mlockall",
	"mmap",
	"mmap2",
	"modify_ldt",
	"mount",
	"move_mount",
	"move_pages",
	"mprotect",
	"mpx",
	"mq_getsetattr",
	"mq_notify",
	"mq_open",
	"mq_timedreceive",
	"mq_timedreceive_time64",
	"mq_timedsend",
	"mq_timedsend_time64",
	"mq_unlink",
	"mremap",
	"msgctl",
	"msgget",
	"msgrcv",
	"msgsnd",
	"msync",
	"multiplexer",
	"munlock",
	"munlockall",
	"munmap",
	"name_to_handle_at",
	"nanosleep",
	"newfstatat",
	"nfsservctl",
	"nice",
	"oldfstat",
	"oldlstat",
	"oldolduname",
	"oldstat",
	"olduname",
	"oldwait4",
	"open",
	"open_by_handle_at",
	"open_tree",
	"openat",
	"pause",
	"pciconfig_iobase",
	"pciconfig_read",
	"pciconfig_write",
	"perf_event_open",
	"personality",
	"pidfd_open",
	"pidfd_send_signal",
	"pipe",
	"pipe2",
	"pivot_root",
	"pkey_alloc",
	"pkey_free",
	"pkey_mprotect",
	"poll",
	"ppoll",
	"ppoll_time64",
	"prctl",
	"pread64",
	"preadv",
	"preadv2",
	"prlimit64",
	"process_vm_readv",
	"process_vm_writev",
	"prof",
	"profil",
	"pselect6",
	"pselect6_time64",
	"ptrace",
	"putpmsg",
	"pwrite64",
	"pwritev",
	"pwritev2",
	"query_module",
	"quotactl",
	"read",
	"readahead",
	"readdir",
	"readlink",
	"readlinkat",
	"readv",
	"reboot",
	"recv",
	"recvfrom",
	"recvmmsg",
	"recvmmsg_time64",
	"recvmsg",
	"remap_file_pages",
	"removexattr",
	"rename",
	"renameat",
	"renameat2",
	"request_key",
	"restart_syscall",
	"rmdir",
	"rseq",
	"rt_sigaction",
	"rt_sigpending",
	"rt_sigprocmask",
	"rt_sigqueueinfo",
	"rt_sigreturn",
	"rt_sigsuspend",
	"rt_sigtimedwait",
	"rt_sigtimedwait_time64",
	"rt_tgsigqueueinfo",
	"rtas",
	"s390_guarded_storage",
	"s390_pci_mmio_read",
	"s390_pci_mmio_write",
	"s390_runtime_instr",
	"s390_sthyi",
	"sched_get_priority_max",
	"sched_get_priority_min",
	"sched_getaffinity",
	"sched_getattr",
	"sched_getparam",
	"sched_getscheduler",
	"sched_rr_get_interval",
	"sched_rr_get_interval_time64",
	"sched_setaffinity",
	"sched_setattr",
	"sched_setparam",
	"sched_setscheduler",
	"sched_yield",
	"seccomp",
	"security",
	"select",
	"semctl",
	"semget",
	"semop",
	"semtimedop",
	"semtimedop_time64",
	"send",
	"sendfile",
	"sendfile64",
	"sendmmsg",
	"sendmsg",
	"sendto",
	"set_mempolicy",
	"set_robust_list",
	"set_thread_area",
	"set_tid_address",
	"set_tls",
	"setdomainname",
	"setfsgid",
	"setfsgid32",
	"setfsuid",
	"setfsuid32",
	"setgid",
	"setgid32",
	"setgroups",
	"setgroups32",
	"sethostname",
	"setitimer",
	"setns",
	"setpgid",
	"setpriority",
	"setregid",
	"setregid32",
	"setresgid",
	"setresgid32",
	"setresuid",
	"setresuid32",
	"setreuid",
	"setreuid32",
	"setrlimit",
	"setsid",
	"setsockopt",
	"settimeofday",
	"setuid",
	"setuid32",
	"setxattr",
	"sgetmask",
	"shmat",
	"shmctl",
	"shmdt",
	"shmget",
	"shutdown",
	"sigaction",
	"sigaltstack",
	"signal",
	"signalfd",
	"signalfd4",
	"sigpending",
	"sigprocmask",
	"sigreturn",
	"sigsuspend",
	"socket",
	"socketcall",
	"socketpair",
	"splice",
	"spu_create",
	"spu_run",
	"ssetmask",
	"stat",
	"stat64",
	"statfs",
	"statfs64",
	"statx",
	"stime",
	"stty",
	"subpage_prot",
	"swapcontext",
	"swapoff",
	"swapon",
	"switch_endian",
	"symlink",
	"symlinkat",
	"sync",
	"sync_file_range",
	"sync_file_range2",
	"syncfs",
	"sys_debug_setcontext",
	"syscall",
	"sysfs",
	"sysinfo",
	"syslog",
	"sysmips",
	"tee",
	"tgkill",
	"time",
	"timer_create",
	"timer_delete",
	"timer_getoverrun",
	"timer_gettime",
	"timer_gettime64",
	"timer_settime",
	"timer_settime64",
	"timerfd",
	"timerfd_create",
	"timerfd_gettime",
	"timerfd_gettime64",
	"timerfd_settime",
	"timerfd_settime64",
	"times",
	"tkill",
	"truncate",
	"truncate64",
	"tuxcall",
	"ugetrlimit",
	"ulimit",
	"umask",
	"umount",
	"umount2",
	"uname",
	"unlink",
	"unlinkat",
	"unshare",
	"uselib",
	"userfaultfd",
	"usr26",
	"usr32",
	"ustat",
	"utime",
	"utimensat",
	"utimensat_time64",
	"utimes",
	"vfork",
	"vhangup",
	"vm86",
	"vm86old",
	"vmsplice",
	"vserver",
	"wait4",
	"waitid",
	"waitpid",
	"write",
	"writev",
}
