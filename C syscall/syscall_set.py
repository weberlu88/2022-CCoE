class Syscall_Set:
	def __init__(self):
		### 五大類別所有的 System call ###
		self.p_list = ["rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "capget", "capset", "nanosleep", "alarm" ,"setitimer" ,"getitimer", "sched_yield", "setns", "mprotect", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "mremap", "mincore", "pause", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "ptrace", "uselib", "personality", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "prctl", "arch_prctl", "create_module", "init_module", "query_module", "delete_module", "tkill", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "get_thread_area", "set_tid_address", "restart_syscall", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "exit_group", "tgkill", "mbind", "set_mempolicy", "get_mempolicy", "waitid", "migrate_pages", "unshare", "set_robust_list", "get_robust_list", "ioprio_set", "ioprio_get", "move_pages", "rt_tgsigqueueinfo", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module", "sched_setattr", "sched_getattr", "seccomp", "getrandom", "bpf", "execveat", "membarrier", "mlock2", "pkey_mprotect", "pkey_alloc", "pkey_free"]
		self.p_list_arm = ["cacheflush", "breakpoint", "cmpxchg", "vm86", "bdflush", "sigprocmask", "sigreturn", "syscall", "idle", "sgetmask", "ssetmask", "sigsuspend", "sigpending", "sigaction", "lock", "signal", "nice", "break", "waitpid", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "capget", "capset", "nanosleep", "alarm" ,"setitimer" ,"getitimer", "sched_yield", "setns", "mprotect", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "mremap", "mincore", "pause", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "ptrace", "uselib", "personality", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "prctl", "create_module", "init_module", "query_module", "delete_module", "tkill", "futex", "sched_setaffinity", "sched_getaffinity", "set_tid_address", "restart_syscall", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "exit_group", "tgkill", "mbind", "set_mempolicy", "get_mempolicy", "waitid", "migrate_pages", "unshare", "set_robust_list", "get_robust_list", "ioprio_set", "ioprio_get", "move_pages", "rt_tgsigqueueinfo", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module", "sched_setattr", "sched_getattr", "seccomp", "getrandom", "bpf", "execveat", "membarrier", "mlock2", "pkey_mprotect", "pkey_alloc", "pkey_free"]
		self.p_list = list(set(self.p_list+self.p_list_arm))

		self.f_list = ["munmap", "mmap", "putpmsg", "getpmsg", "utime", "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "pread64", "pwrite64", "readv", "writev", "access", "select", "msync", "dup", "dup2", "sendfile", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "mknod", "statfs", "fstatfs", "sysfs", "modify_ldt", "pivot_root", "sync", "acct", "mount", "umount2", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "fadvise64", "epoll_wait", "epoll_ctl", "utimes", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "splice", "tee", "sync_file_range", "vmsplice", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd",  "fallocate", "timerfd_settime", "timerfd_gettime", "signalfd4", "eventfd2", "epoll_create1", "dup3", "inotify_init1", "preadv", "pwritev", "fanotify_init", "fanotify_mark", "name_to_handle_at", "open_by_handle_at", "syncfs", "renameat2", "memfd_create", "userfaultfd", "copy_file_range", "preadv2", "pwritev2", "statx", "chroot"]
		self.f_list_arm = ["sync_file_range2", "fstatat64", "fadvise64_64", "fstatfs64", "statfs64", "sendfile64", "fcntl64", "chown32", "fchown32", 'stat64', 'lstat64', 'fstat64', 'lchown32', "ftruncate64", "truncate64", "mmap2", "_newselect", "_llseek", "readdir", "oldlstat", "oldfstat", "umount", "oldstat", "munmap", "mmap", "putpmsg", "getpmsg", "utime", "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "pread64", "pwrite64", "readv", "writev", "access", "select", "msync", "dup", "dup2", "sendfile", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "mknod", "statfs", "fstatfs", "sysfs", "modify_ldt", "pivot_root", "sync", "acct", "mount", "umount2", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "lookup_dcookie", "epoll_create", "remap_file_pages", "getdents64", "epoll_wait", "epoll_ctl", "utimes", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "splice", "tee", "vmsplice", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd",  "fallocate", "timerfd_settime", "timerfd_gettime", "signalfd4", "eventfd2", "epoll_create1", "dup3", "inotify_init1", "preadv", "pwritev", "fanotify_init", "fanotify_mark", "name_to_handle_at", "open_by_handle_at", "syncfs", "renameat2", "memfd_create", "userfaultfd", "copy_file_range", "preadv2", "pwritev2", "statx", "chroot"]
		self.f_list = list(set(self.f_list+self.f_list_arm))

		self.d_list = ["ioctl", "swapon", "swapoff", "iopl", "ioperm", "quotactl", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "io_pgetevents"]
		self.d_list_arm = ['pciconfig_read', 'pciconfig_write', "pciconfig_iobase", "ioctl", "swapon", "swapoff", "iopl", "ioperm", "quotactl", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "io_pgetevents"]
		self.d_list = list(set(self.d_list+self.d_list_arm))

		self.info_list = ["nfsservctl", "madvise", "reboot", "kexec_load", "kexec_file_load", "add_key", "request_key", "keyctl", "perf_event_open", "getpid", "uname", "semget", "semop", "semctl", "msgget", "msgctl", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "ustat", "getpriority", "setpriority", "sched_get_priority_max", "sched_get_priority_min", "_sysctl", "adjtimex", "setrlimit", "settimeofday", "sethostname", "setdomainname", "get_kernel_syms", "gettid", "time", "semtimedop", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "prlimit64", "clock_adjtime", "getcpu", "shmget", "shmat", "shmctl", "shmdt"]
		self.info_list_arm = ['setuid32', 'setgid32', 'setfsuid32', 'setfsgid32', 'setresuid32', 'getresuid32', 'setresgid32', 'getresgid32', 'setregid32', 'getgroups32', 'setgroups32', 'getuid32', 'getgid32', 'geteuid32', 'getegid32', 'setreuid32', "ugetrlimit", "ipc", "olduname", "profil", "oldolduname", "ulimit", "ftime", "stty", "stime", "nfsservctl", "madvise", "reboot", "kexec_load", "kexec_file_load", "add_key", "request_key", "keyctl", "perf_event_open", "getpid", "uname", "semget", "semop", "semctl", "msgget", "msgctl", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "ustat", "getpriority", "setpriority", "sched_get_priority_max", "sched_get_priority_min", "_sysctl", "adjtimex", "setrlimit", "settimeofday", "sethostname", "setdomainname", "get_kernel_syms", "gettid", "time", "semtimedop", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "prlimit64", "clock_adjtime", "getcpu", "shmget", "shmat", "shmctl", "shmdt"]
		self.info_list = list(set(self.info_list+self.info_list_arm))

		self.commu_list = ["mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "pipe", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "msgsnd", "msgrcv", "accept4", "pipe2", "recvmmsg", "sendmmsg"]
		self.commu_list_arm = ["mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", 'send', 'recv', "socketcall", "pipe", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "msgsnd", "msgrcv", "accept4", "pipe2", "recvmmsg", "sendmmsg"]
		self.commu_list = list(set(self.commu_list+self.commu_list_arm))

		self.sys_val_dict = {"Porcess": self.p_list, "File": self.f_list, "Device": self.d_list, "Infomation": self.info_list, "Communication": self.commu_list}


		### 目前在 Family 抓到的 System call ###

		self.original_sys = ['execve', 'open', 'openat', 'read', 'close', 'write', 'rename', 'socket', 'connect', 'send', 'sendto', 'sendmsg', 'recv', 'recvfrom', 'recvmsg', 'ioctl', 'unlink', 'unlinkat', 'rmdir', 'bind', 'mkdir', 'symlink', 'symlinkat', 'link', 'linkat', 'kill', 'ptrace', 'clone', 'fork', 'vfork', 'uname', 'sysinfo']
		self.dofloo_sys = ['brk', 'set_thread_area', 'set_tid_address', 'set_robust_list', 'futex', 'ugetrlimit', 'readlink', 'getcwd',
		 'waitpid', 'exit_group', 'access', 'fstat', 'mmap', 'mprotect', 'arch_prctl', 'munmap', 'getuid', 'getgid', 'getpid',
		  'geteuid', 'getppid', 'stat', 'getegid', 'wait4', 'prlimit64', 'statfs', 'umask', 'fcntl', 'fchown', 'fchmod', 'setsid',
		   'mmap2', '_newselect', 'getsockopt', 'fstat64', 'nanosleep', 'lseek', 'time']
		self.xorddos_sys = ['execve', 'uname', 'brk', 'set_thread_area', 'set_tid_address', 'set_robust_list', 'futex', 'rt_sigaction', 'rt_sigprocmask', 'ugetrlimit', 'readlink', 'clone', 'exit_group', 'setsid', 'open', 'fstat64', 'dup2', 'close', 'stat64', 'gettimeofday', 'lseek', 'read', 'write', 'waitpid', 'nanosleep', 'unlink', 'shmget', 'shmat', 'shmdt', 'symlink', 'mmap2', 'mprotect', 'access', 'openat', 'fstat', 'mmap', 'arch_prctl', 'munmap', 'prlimit64', 'getuid', 'geteuid', 'getgid', 'getegid', 'stat', 'ioctl', 'fcntl', 'getdents', 'lstat', 'pipe', 'wait4', 'getpid', 'getppid', 'rt_sigreturn', 'statfs', 'umask', 'fchown', 'fchmod', 'rename', 'socket', 'sendto', '_newselect', 'fcntl64', 'connect', 'getsockopt', 'mremap', 'time', 'newfstatat', 'setsockopt', 'getsockname', 'sendmsg', 'recvmsg', 'ppoll']
		self.tsunami_sys = ['execve', 'ioctl', 'rt_sigaction', 'vfork', 'wait4', 'exit', 'brk', 'access', 'openat', 'fstat', 'mmap', 'close', 'read', 'mprotect', 'arch_prctl', 'munmap', 'getuid', 'getgid', 'getpid', 'geteuid', 'getppid', 'stat', 'getegid', 'fcntl', 'dup2', 'clone', 'rt_sigreturn', 'exit_group', 'chdir', 'getdents', 'write']

		self.temp_total_sys = set(self.original_sys + self.dofloo_sys + self.xorddos_sys + self.tsunami_sys)

		### 忽略的 sys call ###
		self.p_sig = ["rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "personality", "rt_tgsigqueueinfo", ]
		self.p_exit = ["exit"]

	def get_total_sys(self):
		total_sys = []

		for sys in self.temp_total_sys:
			if sys not in self.p_sig + self.p_exit :
				total_sys.append(sys)

		return 	total_sys


	def get_total_sys_with_type(self, total_sys): # a sys call list that you want to get type
		total_sys_dict = {"Porcess": [], "File": [], "Device": [], "Infomation": [], "Communication": []}

		for sys in total_sys:
			for sys_type in self.sys_val_dict:
				if sys in self.sys_val_dict[sys_type]:
					total_sys_dict[sys_type].append(sys)

		return total_sys_dict

sys_call_set = Syscall_Set()
total_sys = sys_call_set.get_total_sys()
total_sys_with_type = sys_call_set.get_total_sys_with_type(total_sys)
for sys_type in total_sys_with_type:
	print(sys_type, total_sys_with_type[sys_type], "\n")