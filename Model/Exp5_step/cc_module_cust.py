import glob
import re
import subprocess
import os
from datetime import datetime
from graphviz import Digraph        
from datetime import datetime

# Global Variables
STRACE_TIME_FORMAT = '%H:%M:%S.%f' #03:05:34.993967

###### regex #########
RE_PID = 'log.([0-9]*)' # strace.log.(1242).exec
RE_TIME = '^(.*?) ' # (04:31:48.580504) execve(...)
RE_EXECVE_COMMAND = '\", \[\"(.*?)\"' # "/bin/sed", ["(sed)", "-i", "-e", "/exit/d", "/etc/rc.local"], ["SHLVL=1", "_=/usr/bin/strace", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PWD=/"]
RE_EXECVE_OPTION = '\", \[\".*?\", (.*?)\],' # "/bin/sed", [("sed", "-i", "-e", "/exit/d", "/etc/rc.local")], ["SHLVL=1", "_=/usr/bin/strace", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PWD=/"]
RE_CONNECT_ADDR = '(.*?),.*family=(.*),.*htons\(([0-9]*)\).*addr\(\"(.*)\"' # 4, {sa_family=(AF_INET), sin_port=htons(25000), sin_addr=inet_addr("123.129.217.153")}, 16
RE_CONNECT_FAMILY = 'family=(.*?),'
RE_LOG_MERGE_CALL = '^.*? (.*)' # 1874  (06:57:05.321833 brk(0)                  = 0x5dc000)
RE_IOCTL_NAME = 'ifr_name="(.*?)"'
RE_SENDTO_ADDR = '^(.*?),.*htons\((.*?)\).*addr\(\"(.*)\"\)' # (-1), "E\0\0(\", 40, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(23), sin_addr=inet_addr("159.79.135.69")}, 16

ENDPOINT_REGEX = '([0-9]+\.*){4}:[0-9]+'
PRIVATE_IP_REGEX = '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)'

###### Syscall Table ######
process_creation = ['clone', 'fork', 'vfork']
open_file = ['open', 'openat']
# write_file = ['write', 'rename']
write_file = ['write']
info = ['uname', 'sysinfo']
send = ['send', 'sendto', 'sendmsg']
recv = ['recv', 'recvfrom', 'recvmsg']
remove = ['unlink', 'unlinkat', 'rmdir']
link = ['symlink', 'symlinkat', 'link', 'linkat']

#### ignore path ####
ignore_paths = ['/dev/null', 'stdout', 'stderr']

### Trace Parser ### 
def parse_line(log):
    signal = re.search('--- (SIG.*?) {(.*)}', log)
    term = re.search('[0-9]* \+\+\+ (.*) \+\+\+', log)
    
    info = {}
    
    if signal:
        info['type'] = 'sig'
        info['name'] = signal.group(1)
        info['args'] = signal.group(2)
    elif term:
        info['type'] = 'term'
        info['status'] = term.group(1)
    else: 
        info['type'] = 'sys'
        g = re.search(' (.*?)\((.*)\).*= (.*)', log)
        
        # uncompleted function caused by terminating execution
        if not g:
            return None
        
        info['name'] = g.group(1)
        info['args'] = g.group(2)
        info['return'] = g.group(3)
        info['success'] = True
        info['return_msg'] = None
        
        
        # return status: True for success, False for error (startswith E or ?)
        ret = info['return'].split(' ')
        if len(ret) > 1:
            info['return'] = ret[0]
            info['return_msg'] = ' '.join(ret[1:])
            
            # inspect first char of return description ()
            if ret[1].startswith('E'):
                info['success'] = False
                info['return_msg'] = ' '.join(ret[2:])
                
        if info['return'] == '?':
            info['success'] = False
    
    time = re.search(RE_TIME, log).group(1)
    info['time'] = time
    
    return info

def strace_log_merge(path):
    f = open(f'{path}/merge.log', 'w')
    print("Strace merge path:", path)
    p = subprocess.Popen(['strace-log-merge', f'{path}/strace.log'], stdout = f, bufsize=0)
    out, err = p.communicate()
    f.close()
    if err:
        return False
    
    return True

def myprint(syscall, name):
    if syscall['name'] == name:
        print(f"{syscall['args']}: {syscall['return']}")

class Node:
    def __init__(self, name, typ='p'):
        self.name = name
        self.type = typ
        self.technique = ''
        self.tactic = ''
        self.color = None
        self.id = None
class Edge:
    def __init__(self, name, timestamp):
        self.name = name
        self.timestamp = timestamp
        self.technique = ''
        self.tactic = ''
        self.color = None
        self.id = None

### File Descriptor Handler ###
class FileTable:
    def __init__(self):
        self.fd_table = {
            '0': 'stdin',
            '1': 'stdout',
            '2': 'stderr'
        }
    
    def is_used(self, fd):
        return fd in self.fd_table
    
    def add(self, fd, path = None):
        self.fd_table[fd] = path
        
    def rm(self, fd):
        if self.is_used(fd):
            return self.fd_table.pop(fd)
        else:
            return False
        
    def get(self, fd):
        if self.is_used(fd):
            return self.fd_table[fd]
        else:
            return False
        
    def update(self, fd, path):
        if self.is_used(fd):
            self.fd_table[fd] = path
            return True
        else:
            return False
        
    def __str__(self):
        display = '-----------\n'
        for fd, path in self.fd_table.items():
            display += f'{fd}: {path}\n'
        display += '-------------\n'
        return display


### System Call Parser ###
class SyscallParser:
    def __init__(self):        
        self.parse_handler = {
            'execve': self.execve,
            'open': self.openn,
            'openat': self.openat,
            'read': self.read,
            'close': self.close,
            'write': self.write,
            'rename': self.rename,
            'socket': self.socket,
            'connect': self.connect,
            'send': self.send,
            'sendto': self.sendto,
            'sendmsg': self.sendmsg,
            'recv': self.recv,
            'recvfrom': self.recvfrom,
            'recvmsg': self.recvmsg,
            'ioctl': self.ioctl,
            'unlink': self.unlink,
            'unlinkat': self.unlinkat,
            'rmdir': self.rmdir,
            'bind': self.bind,
            'mkdir': self.mkdir,
            'symlink': self.symlink,
            'symlinkat': self.symlinkat,
            'link': self.link,
            'linkat': self.linkat,
            'kill': self.kill,
            'ptrace': self.ptrace,

            ### dofloo v1 ###
            "readlink": self.readlink,
            "waitpid": self.waitpid,
            "access": self.access,
            "fstat": self.fstat,
            "mmap": self.mmap,
            "stat": self.stat,
            "wait4": self.wait4,
            "statfs": self.statfs,
            "fcntl": self.fcntl,
            "fchown": self.fchown,
            "fchmod": self.fchmod,
            "mmap2": self.mmap2,
            "_newselect": self.newselect,
            "getsockopt": self.getsockopt,
            "fstat64": self.fstat64,
            "lseek": self.lseek,

            ### dofloo v2 ###
            "brk": self.brk,
            "set_thread_area": self.set_thread_area,
            "set_tid_address": self.set_tid_address,
            "set_robust_list": self.set_robust_list,
            "futex": self.futex,
            "ugetrlimit": self.ugetrlimit,
            "getcwd": self.getcwd,
            "exit_group": self.exit_group,
            "mprotect": self.mprotect,
            "arch_prctl": self.arch_prctl,
            "munmap": self.munmap,
            "getuid": self.getuid,
            "getgid": self.getgid,
            "getpid": self.getpid,
            "geteuid": self.geteuid,
            "getppid": self.getppid,
            "getegid": self.getegid,
            "prlimit64": self.prlimit64,
            "umask": self.umask,
            "setsid": self.setsid,
            "nanosleep": self.nanosleep,
            "time": self.time,
            
            
            ### xorsddos ###
            "dup2": self.dup2,
            "stat64": self.stat64,
            "gettimeofday": self.gettimeofday,
            "shmget": self.shmget,
            "shmat": self.shmat,
            "shmdt": self.shmdt,
            "getdents": self.getdents,
            "lstat": self.lstat,
            "pipe": self.pipe,
            "fcntl64": self.fcntl64,
            "mremap": self.mremap,
            "newfstatat": self.newfstatat,
            "setsockopt": self.setsockopt,
            "getsockname": self.getsockname,
            "ppoll": self.ppoll,

            ### Tsunami ###
            "chdir": self.chdir
        }
        
        self.isMemSink = True
        self.isTimeSink = True
        self.isNICSink = True
        self.isIDSink = True
        self.isSleepSink = True
#         self.isMemSink = False
#         self.isTimeSink = False
#         self.isNICSink = False
#         self.isIDSink = False
#         self.isSleepSink = False
    

    def chdir(self):
        info = {}
        args  = self.syscall['args'].split(",")
        path = args[0]
        info["path"] = path
        
        return info
    
    def dup2(self):
        info = {}
        args  = self.syscall['args'].split(",")
        old_fd = args[0]
        new_fd = args[1].strip(" ")
        info["old_fd"] = old_fd
        info["new_fd"] = new_fd
        
        return info
    
    def stat64(self):
        info = {}
        args  = self.syscall['args'].split(",")
        path = args[0]
        info["path"] = path
        
        return info
    
    def gettimeofday(self):
        info = {}
        
        if not self.isTimeSink:
            args  = self.syscall['args'].split(",")
            timestamp = int(args[0][1:])
            print(timestamp)
            sys_time = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            info["sys_time"] = sys_time
        else:
            info["sys_time"] = "Timestamp"
        
        return info
    
    def shmget(self):
        info = {}
        shm_id  = self.syscall['return']
        info["shm_id"] = "Shared Memory:" + shm_id
        
        return info
    
    def shmat(self):
        info = {}
        args  = self.syscall['args'].split(",")
        shm_id = args[0]
        shm_addr = self.syscall['return']
        info["shm_id"] = "Shared Memory:" + shm_id # 從 ID 指向 addr
        if self.isMemSink:
            info["shm_addr"] = "Memory Address"
        else:
            info["shm_addr"] = shm_addr
        
        return info
    
    def shmdt(self):
        info = {}
        args  = self.syscall['args'].split(",")
        shm_addr = args[0]
        
        if self.isMemSink:
            info["shm_addr"] = "Memory Address"
        else:
            info["shm_addr"] = shm_addr
        
        return info
    
    def getdents(self):
        info = {}
        args  = self.syscall['args'].split(",")
        fd = args[0]
        info["fd"] = fd
        
        return info
    
    def lstat(self):
        info = {}
        args  = self.syscall['args'].split(",")
        path = args[0]
        info["path"] = path
        
        return info
    
    def pipe(self):
        info = {}
        args  = self.syscall['args'].split(",")
        read_fd = re.findall(r"\d+", args[0])[0]
        write_fd = re.findall(r"\d+", args[1])[0]
        info["read_fd"] = read_fd
        info["write_fd"] = write_fd
        
        return info
    
    def fcntl64(self):
        info = {}
        args  = self.syscall['args'].split(",")
        fd = args[0]
        info["fd"] = fd
        
        return info
    
    def mremap(self):
        info = {}
        args  = self.syscall['args'].split(",")
        m_addr = args[0]

        if self.isMemSink:
            info["m_addr"] = "Memory Address"
        else:
            info["m_addr"] = m_addr
        return info
    
    def newfstatat(self):
        info = {}
        args  = self.syscall['args'].split(",")
        path = args[1]
        info["path"] = path
        
        return info
    
    def setsockopt(self):
        info = {}
        args  = self.syscall['args'].split(",")
        sck_id = args[0]
        info["sck_id"] = sck_id
        
        return info
    def getsockname(self):
        info = {}
        args  = self.syscall['args'].split(",")
        sck_id = args[0]
        info["sck_id"] = sck_id
        
        return info
    
    def ppoll(self):
        info = {}
        args  = self.syscall['args'].split(",")
        fds = re.findall( r"\d+", args[0] ) 
        info["fds"] = fds
        
        return info
    
    
    def brk(self):
        info = {}
        m_addr  = self.syscall['return']
        
        if self.isMemSink:
            info["m_addr"] = "Memory Address"
        else:
            info["m_addr"] = m_addr

        return info
    
    def set_thread_area(self):
        info = {}
        args  = self.syscall['args']
        m_addr = args.split(",")[1].strip(" ").split("=")[1]
        
        if self.isMemSink:
            info["m_addr"] = "Memory Address"
        else:
            info["m_addr"] = m_addr
        return info
    def set_tid_address(self):
        info = {}
        args  = self.syscall['args']
        
        if self.isMemSink:
            info["m_addr"] = "Memory Address"
        else:
            info["m_addr"] = args.strip(" ")
        
        return info
    
    def set_robust_list(self):
        info = {}
        args  = self.syscall['args']
        
        if self.isMemSink:
            info["m_addr"] = "Memory Address"
        else:
            info["m_addr"] = args.split(",")[0]
        
        return info
    
    def futex(self):
        info = {}
        args  = self.syscall['args']
          
        if self.isMemSink:
            info["m_addr"] = "Memory Address"
        else:
            info["m_addr"] = args.split(",")[0]   
        
        return info
    
    def ugetrlimit(self):
        info = {}
        args  = self.syscall['args']
        res_limit = args.split(",")[1].strip(" ").split("=")[1]
        info["res_limit"] = res_limit + " bytes" # bytes
        
        return info
    def getcwd(self):
        info = {}
        args  = self.syscall['args']
        path = args.split(",")[0].strip("\"")
        info["path"] = path
        
        
        return info
    
    def exit_group(self):
        info = {}
        args  = self.syscall['args']
        status_code = args.split(",")[0]
        info["status_code"] = "status:"+ status_code
        
        
        return info
    def mprotect(self):
        info = {}
        args  = self.syscall['args']
        m_addr = args.split(",")[0]
        
        if self.isMemSink:
            info["m_addr"] = "Memory Address"
        else:
            info["m_addr"] = m_addr
        
        
        return info
    
    def arch_prctl(self):
        info = {}
        args  = self.syscall['args']
        m_addr = args.split(",")[1].strip(" ")
        
        if self.isMemSink:
            info["m_addr"] = "Memory Address"
        else:
            info["m_addr"] = m_addr
        
        return info
    def munmap(self):
        info = {}
        args  = self.syscall['args']
        m_addr = args.split(",")[0]
        
        if self.isMemSink:
            info["m_addr"] = "Memory Address"
        else:
            info["m_addr"] = m_addr
        
        
        return info
    
    def getuid(self):
        info = {}
        id  = self.syscall['return']
        if not self.isIDSink:
            info["id"] = id
        else:
            info["id"] = "ID"
        
        return info
    
    def getgid(self):
        info = {}
        id  = self.syscall['return']
        if not self.isIDSink:
            info["id"] = id
        else:
            info["id"] = "ID"
        
        
        return info
    
    def getpid(self):
        info = {}
        id  = self.syscall['return']
        if not self.isIDSink:
            info["id"] = id
        else:
            info["id"] = "ID"
        
        return info
    def geteuid(self):
        info = {}
        id  = self.syscall['return']
        if not self.isIDSink:
            info["id"] = id
        else:
            info["id"] = "ID"
        return info
    
    def getppid(self):
        info = {}
        id  = self.syscall['return']
        if not self.isIDSink:
            info["id"] = id
        else:
            info["id"] = "ID"
        
        return info
    
    def getegid(self):
        info = {}
        id  = self.syscall['return']
        if not self.isIDSink:
            info["id"] = id
        else:
            info["id"] = "ID"
        
        return info
    def prlimit64(self):
        info = {}
        args  = self.syscall['args']
        res_limit = args.split(",")[3].strip(" ").split("=")[1]
        info["res_limit"] = res_limit + " bytes"
        
        return info
    
    def umask(self):
        info = {}
        args  = self.syscall['args']
        permission_mask = args.split(",")[0]
        info["permission_mask"] = "Permission:" + permission_mask
        
        return info
    def setsid(self):
        info = {}
        args  = self.syscall['args']
        id  = self.syscall['return']
        if not self.isIDSink:
            info["id"] = id
        else:
            info["id"] = "ID"      
        
        return info
    
    def nanosleep(self):
        info = {}
        
        if not self.isSleepSink:
            args  = self.syscall['args']
            sec = args.split(",")[0].split("=")[1]
            nsec = args.split(",")[1].split("=")[1][0:-1]
            interval = sec + "s + " + nsec + "ns"
            info["interval"] = interval
        else:
            info["interval"]  = "Sleep Duration"
        return info
    
    def time(self):
        info = {}
        
        # if you encounter a "year is out of range" error the timestamp
        # may be in milliseconds, try `ts /= 1000` in that case
        if not self.isTimeSink:
            timeStamp  = self.syscall['return']
            ts = int(timeStamp)
            sys_time = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            info["sys_time"] = sys_time
        else:
            info["sys_time"] = "Timestamp"
        
        return info
    
    def readlink(self):
        info = {}
        args  = self.syscall['args']
        path = args.split(",")[0].strip("\"")

        info["path"] = path
        
        return info
    
    def waitpid(self):
        info = {}
        args = self.syscall['args']
        pid = args.split(",")[0]
        info["pid"] = pid

        return info

    def access(self):
        info = {}
        args = self.syscall['args']
        path = args.split(",")[0].strip("\"")
        info["path"] = path
        
        return info
    
    def fstat(self):
        info = {}
        args = self.syscall['args']
        fd = args.split(",")[0]
        info["fd"] = fd
        return info

    def mmap(self):
        info = {}
        args = self.syscall['args']
        fd = args.split(",")[-2].strip(" ")
        info["fd"] = fd
        return info
    
    def stat(self):
        info = {}
        args = self.syscall['args']
        path = args.split(",")[0].strip("\"")
        info["path"] = path
        return info

    def wait4(self):
        info = {}
        args = self.syscall['args']
        pid = args.split(",")[0]
        info["pid"] = pid
        return info

    def statfs(self):
        info = {}
        args = self.syscall['args']
        path = args.split(",")[0].strip("\"")
        info["path"] = path
        return info

    def fcntl(self):
        info = {}
        args = self.syscall['args']
        fd = args.split(",")[0]
        info["fd"] = fd
        
        return info

    def fchown(self):
        info = {}
        args = self.syscall['args']
        fd = args.split(",")[0]
        info["fd"] = fd
        return info

    def fchmod(self):
        info = {}
        args = self.syscall['args']
        fd = args.split(",")[0]
        info["fd"] = fd
        return info

    def mmap2(self):
        info = {}
        args = self.syscall['args']
        fd = args.split(",")[-2]
        info["fd"] = fd
        return info

    def newselect(self):
        info = {}
        args = self.syscall['args']
        readfds_sets = re.findall(r'\d+', args.split(",")[1].strip(" "))
        writefds_sets = re.findall(r'\d+', args.split(",")[2].strip(" "))
        exceptfds_sets = re.findall(r'\d+', args.split(",")[3].strip(" "))
        info["readfds_sets"] = readfds_sets
        info["writefds_sets"] = writefds_sets
        info["exceptfds_sets"] = exceptfds_sets
        
        return info
        
    def getsockopt(self):
        info = {}
        args = self.syscall['args']
        sck_id = args.split(",")[0]
        info["sck_id"] = sck_id
        return info

    def fstat64(self):
        info = {}
        args = self.syscall['args']
        fd = args.split(",")[0]
        info["fd"] = fd
        return info

    def lseek(self):
        info = {}
        args = self.syscall['args']
        fd = args.split(",")[0]
        info["fd"] = fd
        return info

    def execve(self):
        info = {}
        
        command = re.search(RE_EXECVE_COMMAND, self.syscall['args'])
        if command:
            command = command.group(1)
        else:
            command = re.search('\"(.*)\"', self.syscall['args'].split(',')[0]).group(1)
            
        option = re.search(RE_EXECVE_OPTION, self.syscall['args'])
        
        # if execve command has option: return option, else option = None
        if option:
            option = option.group(1)
            
        info['command'] = command
        info['option'] = option
        
        return info
    
    def openn(self):
        info = {}
        args = re.search('\"(.*)\", (.*)', self.syscall['args'])
        
        if not args:
            return False
        
        path = args.group(1)
        mode = args.group(2)
        
        info['path'] = path
        info['mode'] = mode
        
        return info
    
    def openat(self):
        info = {}
        args = re.search('\"(.*)\", (.*)', self.syscall['args'])
        
        if not args:
            return False
        
        path = args.group(1)
        mode = args.group(2)
        
        info['path'] = path
        info['mode'] = mode
        
        return info
    
    def close(self):
        info = {}
        info['fd'] = self.syscall['args']
        
        return info
    
    def write(self):
        info = {}
        info['fd'] = self.syscall['args'].split(',')[0]
        return info
    
    def rename(self):
        info = {}
        args = self.syscall['args'].split(',')
        path_tmp = args[0].strip(" ").strip("\"")
        path_target = args[1].strip(" ").strip("\"")
        info['path_tmp'] = path_tmp
        info['path_target'] = path_target
#         info['path'] = re.search('\"(.*)\"', args[1]).group(1)
        
        return info
    
    def read(self):
        info = {}
        info['fd'] = self.syscall['args'].split(',')[0]
        return info
    
    def socket(self):
        info = {}
        info['fd'] = self.syscall['return']
        
        data = self.syscall['args'].split(',')
        info['family'] = data[0].strip()
        
        proto = data[1].strip()
        if proto == 'SOCK_STREAM':
            info['proto'] = 'TCP'
        elif proto == 'SOCK_DGRAM':
            info['proto'] = 'UDP'
        else:
            info['proto'] = proto
        
        return info
    
    def bind(self):
        info = {}
        family = re.search(RE_CONNECT_FAMILY, self.syscall['args']).group(1)
        if family not in ['AF_INET', 'PF_INET']:
            info['family'] = family
            return info
        
        conn = re.search(RE_CONNECT_ADDR, self.syscall['args'])
        
        info['fd'] = conn.group(1)
        info['family'] = conn.group(2)
        info['addr'] = conn.group(4) + ':' + conn.group(3)
        
        return info
    
    def connect(self):
        info = {}
        family = re.search(RE_CONNECT_FAMILY, self.syscall['args']).group(1)
        if family not in ['AF_INET', 'PF_INET']:
            info['family'] = family
            return info
        
        conn = re.search(RE_CONNECT_ADDR, self.syscall['args'])
        
        info['fd'] = conn.group(1)
        info['family'] = conn.group(2)
        info['addr'] = conn.group(4) + ':' + conn.group(3)
        
        return info
    
    def send(self):
        info = {}
        info['fd'] = self.syscall['args'].split(',')[0].strip()
        
        return info
    
    def sendto(self):
        # sendto(int sockfd, const void *buf, size_t len, int flags,
        #const struct sockaddr *dest_addr, socklen_t addrlen);
        info = {}
        send = re.search(RE_SENDTO_ADDR, self.syscall['args'])
        
        # sendto that have no addr info like AF_UNIX or dest_addr = NULL
        if not send:
            info['fd'] = self.syscall['args'].split(',')[0].strip()
            return info
        
        info['fd'] = send.group(1)
        info['addr'] = send.group(3) + ':' + send.group(2)
        
        return info
    
    def sendmsg(self):
        info = {}
        info['fd'] = self.syscall['args'].split(',')[0].strip()
        
        return info
    
    def recv(self):
        info = {}
        info['fd'] = self.syscall['args'].split(',')[0].strip()
        
        return info
    
    def recvfrom(self):
        info = {}
        recv = re.search(RE_SENDTO_ADDR, self.syscall['args'])
        
        # recvfrom that have no addr info like AF_UNIX or dest_addr = NULL
        if not recv:
            info['fd'] = self.syscall['args'].split(',')[0].strip()
            return info
        
        info['fd'] = recv.group(1)
        info['addr'] = recv.group(3) + ':' + recv.group(2)
        
        return info
    
    def recvmsg(self):
        info = {}
        info['fd'] = self.syscall['args'].split(',')[0].strip()
        
        return info
    
    def ioctl(self):
        info = {}
        #ioctl(0, SIOCGIFADDR, {ifr_name="eth0", ifr_addr={AF_INET, inet_addr("10.0.2.15")}})
        data = self.syscall['args'].split(',')
        info['fd'] = data[0].strip()
        info['req'] = data[1].strip()
        
        if info['req'] == 'SIOCGIFADDR':
            if not self.isNICSink:
                info['dev'] = re.search(RE_IOCTL_NAME, self.syscall['args']).group(1)
            else:
                info['dev'] = "NIC"
            
        return info
    
    def unlink(self):
        info = {}
        info['path'] = re.search('\"(.*)\"', self.syscall['args']).group(1)
        
        return info
    
    def unlinkat(self):
        info = {}
        info['path'] = re.search('\"(.*)\"', self.syscall['args'].split(',')[1]).group(1)
        
        return info
    
    def symlink(self):
        # int symlink(const char *target, const char *linkpath);
        info = {}
        t, l = self.syscall['args'].split(',')
        info['target'] = re.search('\"(.*)\"', t).group(1)
        info['link'] = re.search('\"(.*)\"', l).group(1)
        
        return info
        
    def symlinkat(self):
        # int symlinkat(const char *target, int newdirfd, const char *linkpath);
        info = {}
        t, f, l = self.syscall['args'].split(',')
        info['target'] = re.search('\"(.*)\"', t).group(1)
        info['link'] = re.search('\"(.*)\"', l).group(1)
        
        return info
    
    def link(self):
        # int link(const char *oldpath, const char *newpath);
        info = {}
        t, l = self.syscall['args'].split(',')
        info['target'] = re.search('\"(.*)\"', t).group(1)
        info['link'] = re.search('\"(.*)\"', l).group(1)
        
        return info
    
    def linkat(self):
        # int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
        info = {}
        d = self.syscall['args'].split(',')
        info['target'] = re.search('\"(.*)\"', d[1]).group(1)
        info['link'] = re.search('\"(.*)\"', d[3]).group(1)
        
        return info
    
    def rmdir(self):
        # int rmdir(const char *pathname);
        info = {}
        info['path'] = re.search('\"(.*)\"', self.syscall['args']).group(1)
        
        return info
    
    def mkdir(self):
        # int mkdir(const char *pathname, mode_t mode); 
        info = {}
        info['path'] = re.search('\"(.*)\"', self.syscall['args'].split(',')[0]).group(1)
        
        return info
    
    def kill(self):
        #int kill(pid_t pid, int sig);
        info = {}
        info['pid'] = self.syscall['args'].split(',')[0]
        
        return info
    
    def ptrace(self):
        info = {}
        args = self.syscall['args'].split(',')
        info['req'] = args[0]
        
        if len(args) >= 2:
            info['pid'] = args[1].strip()
        
        return info
        
    def parse(self, syscall): # syscall is a dict returned by parse_line()
        self.syscall = syscall
        self.name = syscall['name']
        
        return self.parse_handler[self.name]()
    
    
sys_parser = SyscallParser()

### Attack Scenario Graph Main Class Definition ###
class AttackGraph:
    def __init__(self, path):
        self.malware_hash = path.split('/')[-1]
        self.traces = sorted(glob.glob(path + '/strace*'))
        self.proc_id  = -1 # initialize
        self.traces_lines = 0
        self.trigger_lines = 0
        self.graph = {}
        self.edges = {}
        self.current_dir = ""
        

        self.proc_node_map = {}
        self.file_table = FileTable()
        
        # record seen file path
        self._file_node_map = {}
        
        # unique ip set
        self.unique_ip = set()
        
        # handler function
        self._syscall_handler_table = {
            'process': self._process,
            'read': self._read,
            'open': self._openn,
            'execve': self._execve,
            'close': self._close,
            'write': self._write,
            'socket': self._socket,
            'connect': self._connect,
            'info': self._info,
            'send': self._send,
            'recv': self._recv,
            'ioctl': self._ioctl,
            'rm': self._rm,
            'bind': self._bind,
            'mkdir': self._mkdir,
            'link': self._link,
            'kill': self._kill,
            'ptrace': self._ptrace
        }

        self.added_handler_table = [
            ### Dofloo v1 ###
            "readlink",
            "waitpid",
            "access",
            "fstat",
            "mmap",
            "stat",
            "wait4",
            "statfs",
            "fcntl",
            "fchown",
            "fchmod",
            "mmap2",
            "_newselect",
            "getsockopt",
            "fstat64",
            "lseek",
            
            ### Dofloo v2 ###
            "brk",
            "set_thread_area",
            "set_tid_address",
            "set_robust_list",
            "futex",
            "ugetrlimit",
            "getcwd",
            "exit_group",
            "mprotect",
            "arch_prctl",
            "munmap",
            "getuid",
            "getgid",
            "getpid",
            "geteuid",
            "getppid",
            "getegid",
            "prlimit64",
            "umask",
            ### Note ###
            # setsid()  runs  a  program  in a new session. The command calls fork(2) if already a process group leader.
            # Otherwise, it executes a program in the current proces
            # 我們已經有處理 clone、fork 來創建 new program，不需要再這裡再做一次
#             "setsid",
            "nanosleep",
            "time",
            
            ### xorddos ###
            "dup2",
            "stat64",
            "gettimeofday",
            "shmget",
            "shmat",
            "shmdt",
            "getdents",
            "lstat",
            "pipe",
            "fcntl64",
            "mremap",
            "newfstatat",
            "setsockopt",
            "getsockname",
            "ppoll",

            ### Tsunami ###
            "chdir",
            
            ### rename ###
            "rename"
        ]
        
        # self.added_handler_table = {
        #     "readlink": self._readlink,
        #     "waitpid": self._waitpid,
        #     "access": self._access,
        #     "fstat": self._fstat,
        #     "mmap": self._mmap,
        #     "stat": self._stat,
        #     "wait4": self._wait4,
        #     "statfs": self._statfs,
        #     "fcntl": self._fcntl,
        #     "fchown": self._fchown,
        #     "fchmod": self._fchmod,
        #     "mmap2": self._mmap2,
        #     "_newselect": self._newselect,
        #     "getsockopt": self._getsockopt,
        #     "fstat64": self._fstat64,
        #     "lseek": self._lseek
        # }
        
        self._path = path
        self.exec = False
        self.step_list = []
        self.set_of_object = {}
        self.set_of_object_summary = {"File":0, "Process":0, "Net":0, "Memory":0, "Other":0}
        self.set_of_object_summary_list = {"File":[], "Process":[], "Net":[], "Memory":[], "Other":[]}
        
        self.isDuplicate = True
        self.isHardFilter = True
        self.hardRule = [".*/lib.*","/usr/lib/.*", "/etc/ld.so.*", "/usr/local/lib/.*", ".*locale.*"] # 去除
        
        self.file_filter = ["/etc/sed", "/etc/selinux"] # 保留
        
    def replace_cwd(self, node):
        cwd = '/prober/host_share/'
        if node.name.split('/')[-1] == self.malware_hash:
            node.name = 'malware'
    
        if node.name.startswith(cwd):
            node.name = './' + node.name.replace(cwd, '')
    
    # connect two nodes
    def _connect_node(self, from_node, to_node, edge):
        #if to_node.name == 'sysinfo':
        #    print(f'Connect {from_node.name} to {to_node.name}')
        self.replace_cwd(from_node)
        self.replace_cwd(to_node)
        
        self.graph[from_node].append(to_node)
        self.edges[(from_node, to_node, edge.name)] = edge
        
        ### step list ###
        if self.isDuplicate:
            self.step_list.append((from_node, to_node, edge.name))
        else:
            if (from_node, to_node, edge.name) not in self.step_list:
                self.step_list.append((from_node, to_node, edge.name))
        


    
    # connect proc to file if there is no edge between them currently
    # from_proc: edge direction
    # if True: current node to file node (write, exec...). False: file node to current node (read)
    def _connect_proc_file(self, path, edge_name, time, from_proc = True, node_typ = 'f'):
        
        # if file node not exist: create new node, else: connect current node to exist file node
        if path not in self._file_node_map and path not in self.proc_node_map:
            child_node = Node(path, node_typ)
            
            if from_proc:
                from_node = self.current_node
                to_node = child_node
            else:
                from_node = child_node
                to_node = self.current_node
            
            if node_typ != 'p':
                self._file_node_map[path] = child_node
            else:
                self.proc_node_map[path] = child_node
            
            self.graph[child_node] = []
            
            self._connect_node(from_node, to_node, Edge(edge_name, time)) 
        # file node exist
        else:
            if node_typ != 'p':
                child_node = self._file_node_map[path]
            else:
                child_node = self.proc_node_map[path]
                
            if from_proc:
                from_node = self.current_node
                to_node = child_node
            else:
                from_node = child_node
                to_node = self.current_node
                
            # if curent node has not connected to file node (escape loop in strace.log)
            if not self.isDuplicate :
                if (from_node, to_node, edge_name) not in self.edges:
                    self._connect_node(from_node, to_node, Edge(edge_name, time))

            else:
                self._connect_node(from_node, to_node, Edge(edge_name, time))
  
    
    # remove connection between two nodes
    def _rm_connect(self, edge):
        from_node, to_node, _ = edge
        self.graph[from_node].remove(to_node)
        self.edges.pop(edge)
        
    def _find_path_by_fd(self, fd, time):
        path = 'Unknown'
        local_file_table = FileTable()
        
        # malware use only one ip
        if len(self.unique_ip) == 1:
            path = list(self.unique_ip)[0]
        
        # rebuild fd table from first line of merge.log
        else:
            if not os.path.isfile(f'{self._path}/merge.log'):
                strace_log_merge(self._path)

            with open(f'{self._path}/merge.log', 'r') as f:
                for line in f:
                    try:
                        line2 = re.search(RE_LOG_MERGE_CALL, line).group(1)
                    except AttributeError:
                        print(line)
                        raise
                    syscall = parse_line(line2)

                    if not syscall or syscall['type'] != 'sys':
                        continue

                    name = syscall['name']

                    # if found: get path and update class file_table
                    if syscall['time'] == time:
                        path = local_file_table.get(fd)
                        if not path:
                            pass
                            #print(syscall)
                            #raise KeyError('_find_path_by_fd: fd not found.')
                        self.file_table.update(fd, path)
                        break

                    # build fd table
                    if syscall['success']:
                        if name in open_file:
                            info = sys_parser.parse(syscall)
                            local_file_table.add(syscall['return'], info['path'])

                            # print("syscall:", syscall)
                            # print(local_file_table)
                        elif name == 'socket':
                            info = sys_parser.parse(syscall)
                            # update fd table if create socket successfully
                            if info['family'] not in ['AF_INET', 'PF_IENT']:
                                local_file_table.add(fd, info['family'])
                            else:
                                local_file_table.add(syscall['return'])

                        elif name == 'close':
                            info = sys_parser.parse(syscall)
                            local_file_table.rm(info['fd'])
                            
                    elif name == 'connect':
                        info = sys_parser.parse(syscall)
                        # ignore IPC usage
                        if info['family'] not in ['AF_INET', 'PF_INET']:
                            return
                        local_file_table.update(info['fd'], info['addr'])
        
        
        return path
        
    def _process(self, syscall):
        pid = syscall['return']
        child_node = Node(pid)
        self.proc_node_map[pid] = child_node
        self.graph[child_node] = []

        # if self._inside_execve:
        if self.exec:
            edge = Edge('exec', syscall['time'])
            
        else:
            edge = Edge(syscall['name'], syscall['time'])

        self._connect_node(self.current_node, child_node, edge)
    
    def _execve(self, syscall):
        self._inside_execve = True # True will not draw the system file
        self.exec = True # Flag for present exec edge
        info = sys_parser.parse(syscall)
        if info['command'].split('/')[-1] == self.malware_hash:
            info['command'] = 'malware'

        # set current ndoe name = execve command
        self.current_node.name = info['command']

        # find target file if command has option
        if info['option']:
            self._execve_options = [ re.search('\"(.*)\"', opt).group(1) for opt in info['option'].split(',')]
        else:
            self._execve_options = []

    def _added_handler(self, syscall):
        info = sys_parser.parse(syscall)
        # for file
        if("fd" in info or "path" in info):
            
            if("fd" in info):
                fd = info['fd']
                path = self.file_table.get(fd)
                
                ### inside_execve = False ###
                if not path and not self._inside_execve:
                    path = self._find_path_by_fd(fd, syscall['time'])
                
                ### inside_execve = True : Not draw the common file###
                elif path and self._inside_execve == True:
                    
                    isCommonFile = True
                    for p in self.file_filter:
                        if p in path:
                            isCommonFile = False
                            break
                        
                    if isCommonFile:
                        return    
                
                if path in ignore_paths:
                    return
            elif("path" in info):
                path = info["path"]

            
            edge_name = syscall["name"]

            

            # if fd exist in fd table 
            if path:
                if path[0] != "/":
                    path = self.current_dir + path
                
                ### hard filter the /lib/*、 /etc/ld.so ###
                if self.isHardFilter:

                    for rule in self.hardRule:
                        isMatch = re.match(rule, path)
                        if isMatch:
                            # if path.find('locale') >= 0:
                            #     print('  hardRule return, edge_name is', edge_name, 'path is', path)
                            return
                    
                    
               # if file appear in execve or currently not in execve
#                 if (self._inside_execve and (path in self._execve_options)) or not self._inside_execve:
                # file node not exist
                if path not in self._file_node_map:
                    child_node = Node(path, typ='f')
                    self._file_node_map[path] = child_node
                    self.graph[child_node] = []
                    self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))


                # file node exist
                else:
                    child_node = self._file_node_map[path]

                    # if curent node has connected to file node open(), remove open and connect edge
#                     replace_edge_name = ['open']
#                     for exist_edge_name in replace_edge_name:
#                         edge = (self.current_node, child_node, exist_edge_name)
#                         if edge in self.edges:
#                             self._rm_connect(edge)

                    # if has conected with write(), don't re-connect current node and child node
                    if not self.isDuplicate :
                        if (self.current_node, child_node, edge_name) not in self.edges:
                            self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                    else:
                        self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))

            ### For chdir ###
            if syscall["name"] == "chdir":
                self.current_dir = info["path"].strip("\"") + "/"

        # For process
        elif("pid" in info):
            
            pid = info["pid"]
            edge_name = syscall["name"]
 
            if pid in self.proc_node_map: # the process id need to have alreay been create, then we just can manipulate it
                child_node = self.proc_node_map[pid]
                
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
            else:
                node_name = "NO_PID"
                if node_name not in self._file_node_map:
                    child_node = Node(node_name)
                    self._file_node_map[node_name] = child_node
                    self.graph[child_node] = []
                    self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                else:
                    child_node = self._file_node_map[node_name]
                    if not self.isDuplicate :
                        if (child_node, self.current_node, edge_name) not in self.edges:
                            self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                    else:
                        self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                    
        # For socket
        elif("sck_id" in info):
            sck_id = info["sck_id"]
            path = self._find_path_by_fd(sck_id, syscall['time']) # get socket ip addr
            edge_name = syscall["name"]

            # file node not exist
            if path not in self._file_node_map:
                child_node = Node(path, typ='n')
                self._file_node_map[path] = child_node
                self.graph[child_node] = []
                self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))

            # file node exist
            else:
                child_node = self._file_node_map[path]
                # if curent node has connected to file node open(), remove open edge
                # replace_edge_name = ['connect']
                # for exist_edge_name in replace_edge_name:
                #     edge = (self.current_node, child_node, exist_edge_name)
                #     if edge in self.edges:
                #         self._rm_connect(edge)

                # # if has conected with recv(), don't re-connect current node and child node
                # if (child_node, self.current_node, edge_name) not in self.edges:
                # if (self.current_node, child_node, edge_name) not in self.edges:
                self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))
                
        ### non-classify type ###
        elif("m_addr" in info):
            # return
            m_addr = info["m_addr"]
            edge_name = syscall["name"]

            # if "Memory Addr" not in self._file_node_map:
            #     child_node = Node("Memory Addr", typ='m_addr')
            #     self._file_node_map["Memory Addr"] = child_node
            #     self.graph[child_node] = []
            #     # if not self._inside_execve:
            #     self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))                
            # else:
            #     child_node = self._file_node_map["Memory Addr"]
            #     if (self.current_node, child_node, edge_name) not in self.edges:
            #         self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))  

            # node not exist
            if m_addr not in self._file_node_map:
                child_node = Node(m_addr, typ='m_addr')
                self._file_node_map[m_addr] = child_node
                self.graph[child_node] = []
                # if not self._inside_execve:
                self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                # else:
                #     self._connect_node(self.proc_node_map[self.proc_id], child_node,  Edge(edge_name, syscall['time']))
                    
            # node exist
            else:
                child_node = self._file_node_map[m_addr]
                # if not self._inside_execve:  
                # don't re-connect current node and child node   
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                        
                else:
                    self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                    
                # else:
                #     # don't re-connect current node and child node
                #     if (self.proc_node_map[self.proc_id], child_node, edge_name) not in self.edges:
                #         self._connect_node(self.proc_node_map[self.proc_id] , child_node,  Edge(edge_name, syscall['time']))
                
        elif("path_tmp" in info):
            path_tmp = info["path_tmp"]
            path_target = info["path_target"]
            edge_name = syscall["name"]
            
            ### create the src and dest node ###
            if path_tmp not in self._file_node_map:
                source_node = Node(path_tmp + "_NOT_FOUND", typ='f')
                self._file_node_map[path_tmp] = source_node
                self.graph[source_node] = []
            else:
                source_node = self._file_node_map[path_tmp]
                
            if path_target not in self._file_node_map:
                dest_node = Node(path_target + "_NOT_FOUND", typ='f')
                self._file_node_map[path_target] = dest_node
                self.graph[dest_node] = []
            else:
                dest_node = self._file_node_map[path_target]
                

            
            ### connect node ###
            if not self.isDuplicate :
                if (source_node, dest_node, edge_name) not in self.edges:
                    self._connect_node(source_node , dest_node,  Edge(edge_name, syscall['time']))
                    
            else:
                self._connect_node(source_node , dest_node,  Edge(edge_name, syscall['time']))
                
                    
        elif("res_limit" in info):
            res_limit = info["res_limit"]
            edge_name = syscall["name"]
            # node not exist
            if res_limit not in self._file_node_map:
                child_node = Node(res_limit, typ='else')
                self._file_node_map[res_limit] = child_node
                self.graph[child_node] = []
                # if not self._inside_execve:
                self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                # else:
                #     self._connect_node(self.proc_node_map[self.proc_id] , child_node,  Edge(edge_name, syscall['time']))
            # node exist
            else:
                child_node = self._file_node_map[res_limit]
                # if not self._inside_execve:  
                # don't re-connect current node and child node
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                    
                else:
                    self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                    
                # else:
                #     # don't re-connect current node and child node
                #     if (self.proc_node_map[self.proc_id], child_node, edge_name) not in self.edges:
                #         self._connect_node(self.proc_node_map[self.proc_id] , child_node,  Edge(edge_name, syscall['time']))            
            
        elif("status_code" in info):
            status_code = info["status_code"]
            edge_name = syscall["name"]
            # node not exist
            if status_code not in self._file_node_map:
                child_node = Node(status_code, typ='else')
                self._file_node_map[status_code] = child_node
                self.graph[child_node] = []
                self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))

            # node exist
            else:
                child_node = self._file_node_map[status_code]

                # don't re-connect current node and child node
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
  
        elif("id" in info):
            id = info["id"]
            edge_name = syscall["name"]
            # node not exist
            if id not in self._file_node_map:
                child_node = Node(id, typ='else')
                self._file_node_map[id] = child_node
                self.graph[child_node] = []
                # if not self._inside_execve:
                self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                # else:
                    # self._connect_node(self.proc_node_map[self.proc_id] , child_node,  Edge(edge_name, syscall['time']))
            # node exist
            else:
                child_node = self._file_node_map[id]
                # if not self._inside_execve:  
                # don't re-connect current node and child node
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
  

        elif("permission_mask" in info):
            permission_mask = info["permission_mask"]
            edge_name = syscall["name"]
            # node not exist
            if permission_mask not in self._file_node_map:
                child_node = Node(permission_mask, typ='else')
                self._file_node_map[permission_mask] = child_node
                self.graph[child_node] = []
                # if not self._inside_execve:
                self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                # else:
                #     self._connect_node(self.proc_node_map[self.proc_id] , child_node,  Edge(edge_name, syscall['time']))
            # node exist
            else:
                child_node = self._file_node_map[permission_mask]
                # if not self._inside_execve:  
                # don't re-connect current node and child node
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                # else:
                #     # don't re-connect current node and child node
                #     if (self.proc_node_map[self.proc_id], child_node, edge_name) not in self.edges:
                #         self._connect_node(self.proc_node_map[self.proc_id] , child_node,  Edge(edge_name, syscall['time']))   
        elif("interval" in info):
            interval = info["interval"]
            edge_name = syscall["name"]
            # node not exist
            if interval not in self._file_node_map:
                child_node = Node(interval, typ='else')
                self._file_node_map[interval] = child_node
                self.graph[child_node] = []
                # if not self._inside_execve:
                self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                # else:
                #     self._connect_node(self.proc_node_map[self.proc_id] , child_node,  Edge(edge_name, syscall['time']))
            # node exist
            else:
                child_node = self._file_node_map[interval]
                # if not self._inside_execve:  
                # don't re-connect current node and child node
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                # else:
                #     # don't re-connect current node and child node
                #     if (self.proc_node_map[self.proc_id], child_node, edge_name) not in self.edges:
                #         self._connect_node(self.proc_node_map[self.proc_id] , child_node,  Edge(edge_name, syscall['time'])) 
        elif("sys_time" in info):
            sys_time = info["sys_time"]
            edge_name = syscall["name"]
            # node not exist
            if sys_time not in self._file_node_map:
                child_node = Node(sys_time, typ='else')
                self._file_node_map[sys_time] = child_node
                self.graph[child_node] = []
                # if not self._inside_execve:
                self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                # else:
                #     self._connect_node(self.proc_node_map[self.proc_id] , child_node,  Edge(edge_name, syscall['time']))
            # node exist
            else:
                child_node = self._file_node_map[sys_time]
                # if not self._inside_execve:  
                # don't re-connect current node and child node
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                else:
                     self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                # else:
                #     # don't re-connect current node and child node
                #     if (self.proc_node_map[self.proc_id], child_node, edge_name) not in self.edges:
                #         self._connect_node(self.proc_node_map[self.proc_id] , child_node,  Edge(edge_name, syscall['time'])) 
        elif("old_fd" in info and "new_fd" in info):
            old_fd = info["old_fd"]
            new_fd = info["new_fd"]   
            self.file_table.update( new_fd, self.file_table.get(old_fd) )

        elif("shm_id" in info):
            shm_id = info["shm_id"]
            edge_name = syscall["name"]
            
            if ("shm_addr" not in info):
                if shm_id not in self._file_node_map:
                    child_node = Node(shm_id, typ='else')
                    self._file_node_map[shm_id] = child_node
                    self.graph[child_node] = []
                    # if not self._inside_execve:
                    self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                else:
                    child_node = self._file_node_map[shm_id]
                    if not self.isDuplicate :
                        if (self.current_node, child_node, edge_name) not in self.edges:
                            self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                    else:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                    
            else:
                # return 
                shm_addr = info["shm_addr"]
#                 print("shm_addr:", shm_addr)
                # if "Memory Addr" not in self._file_node_map:
                #     child_node = Node("Memory Addr", typ='m_addr')
                #     self._file_node_map["Memory Addr"] = child_node
                #     self.graph[child_node] = []
                #     # if not self._inside_execve:
                #     self._connect_node(self._file_node_map[shm_id] , child_node,  Edge(edge_name, syscall['time']))                  
                # else:
                #     child_node = self._file_node_map["Memory Addr"]
                #     if (self.current_node, child_node, edge_name) not in self.edges:
                #         self._connect_node(self._file_node_map[shm_id] , child_node,  Edge(edge_name, syscall['time']))   

                # not have the addr
                if shm_addr not in self._file_node_map:

                    child_node = Node(shm_addr, typ='m_addr')
                    self._file_node_map[shm_addr] = child_node
                    self.graph[child_node] = []
                    # if not self._inside_execve:
                    self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                    
                # if have addr, the id connect to the addr    
                else:
                    child_node = self._file_node_map[shm_addr]
                    if not self.isDuplicate :
                        if (self.current_node, child_node, edge_name) not in self.edges:
                            self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                    else:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                
                        
        elif("read_fd" in info and "write_fd" in info):
            read_fd = info["read_fd"]
            write_fd = info["write_fd"]
            edge_name = syscall["name"]
            
            read_node = "Pipe " + read_fd + " : read end from Pipe " + write_fd
            write_node = "Pipe " + write_fd + " : write end to Pipe " + read_fd
            
            self.file_table.add(read_fd, read_node)
            self.file_table.add(write_fd, write_node)
            
            if read_node not in self._file_node_map:
                child_node = Node(read_node, typ='pipe')
                self._file_node_map[read_node] = child_node
                self.graph[child_node] = []
                # if not self._inside_execve:
                self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
            else:
                child_node = self._file_node_map[read_node]
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
            
            if write_node not in self._file_node_map:
                child_node = Node(write_node, typ='pipe')
                self._file_node_map[write_node] = child_node
                self.graph[child_node] = []
                # if not self._inside_execve:
                self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))
            else:
                child_node = self._file_node_map[write_node]
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))    
                else:
                    self._connect_node(self.current_node , child_node,  Edge(edge_name, syscall['time']))  
                    
        elif("fds" in info or "readfds_sets" in info) :
            if "fds" in info:
                fds = info["fds"]
                edge_name = syscall["name"]
                for fd in fds:
                    path = self.file_table.get(fd)
                    
                     ### inside_execve = False ###
                    if not path and not self._inside_execve:
                        path = self._find_path_by_fd(fd, syscall['time'])
                        
                    ### inside_execve = True : Not draw the common file###
                    elif path and self._inside_execve == True:
                        isCommonFile = True
                        for p in self.file_filter:
                            if p in path:
                                isCommonFile = False
                                break

                        if isCommonFile:
                            return    
                    if path in ignore_paths:
                        continue
                    
                    # if fd exist in fd table 
                    if path:
                        if path[0] != "/":
                            path = self.current_dir + path
                        # if file appear in execve or currently not in execve
#                         if (self._inside_execve and (path in self._execve_options)) or not self._inside_execve:
                        

                        ### hard filter the /lib/*、 /etc/ld.so ###
                        if self.isHardFilter:
                
                            for rule in self.hardRule:
                                isMatch = re.match(rule, path)
                                if isMatch:
                                    return
                            
                        # file node not exist
                        if path not in self._file_node_map:
                            child_node = Node(path, typ='f')
                            self._file_node_map[path] = child_node
                            self.graph[child_node] = []
                            self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))


                        # file node exist
                        else:
                            child_node = self._file_node_map[path]

                            # if curent node has connected to file node open(), remove open and connect edge
#                             replace_edge_name = ['open']
#                             for exist_edge_name in replace_edge_name:
#                                 edge = (self.current_node, child_node, exist_edge_name)
#                                 if edge in self.edges:
#                                     self._rm_connect(edge)

                            # if has conected with write(), don't re-connect current node and child node
                            if not self.isDuplicate :
                                if (self.current_node, child_node, edge_name) not in self.edges:
                                    self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                            else:
                                self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                                    
            else:
                for key in info:
                    if len(info[key]) != 0:

                        fds = info[key]
                        edge_name = syscall["name"]
                        for fd in fds:
                            path = self.file_table.get(fd)
                            if not path and not self._inside_execve:
                                path = self._find_path_by_fd(fd, syscall['time'])
                                
                            ### inside_execve = True : Not draw the common file###
                            elif path and self._inside_execve == True:

                                isCommonFile = True
                                for p in self.file_filter:
                                    if p in path:
                                        isCommonFile = False
                                        break

                                if isCommonFile:
                                    return     
                                
                            if path in ignore_paths:
                                continue
                            
                            # if fd exist in fd table 
                            if path:
                                if path[0] != "/":
                                    path = self.current_dir + path
                                # if file appear in execve or currently not in execve
#                                 if (self._inside_execve and (path in self._execve_options)) or not self._inside_execve:

                                ### hard filter the /lib/*、 /etc/ld.so ###
                                if self.isHardFilter:
                                    
                                    for rule in self.hardRule:
                                        isMatch = re.match(rule, path)
                                        if isMatch:
                                            return
                            
                                # file node not exist
                                if path not in self._file_node_map:
                                    child_node = Node(path, typ='f')
                                    self._file_node_map[path] = child_node
                                    self.graph[child_node] = []
                                    self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))


                                # file node exist
                                else:
                                    child_node = self._file_node_map[path]

                                    # if curent node has connected to file node open(), remove open and connect edge
#                                     replace_edge_name = ['open']
#                                     for exist_edge_name in replace_edge_name:
#                                         edge = (self.current_node, child_node, exist_edge_name)
#                                         if edge in self.edges:
#                                             self._rm_connect(edge)

                                    # if has conected with write(), don't re-connect current node and child node
                                    if not self.isDuplicate :
                                        if (self.current_node, child_node, edge_name) not in self.edges:
                                            self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                                    else:
                                        self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
        
    def _read(self, syscall):
        info = sys_parser.parse(syscall)
        fd = info['fd']
        path = self.file_table.get(fd)
 
        # fd may open in parent process
        if not path and not self._inside_execve:
            path = self._find_path_by_fd(fd, syscall['time'])

        ### inside_execve = True : Not draw the common file###
        elif path and self._inside_execve == True:
            isCommonFile = True
            for p in self.file_filter:
                if p in path:
                    isCommonFile = False
                    break

            if isCommonFile:
                return     
            
        # ignore paths
        if path in ignore_paths:
            return
        
        edge_name = 'read'
#         if not syscall['success']:
#             edge_name = f"read{syscall['return_msg']}"
        
        # if fd exist in fd table 
        if path:
            
            ### For pipe ###
            if("Pipe" in path):
                read_fd = path.split(" ")[1]
                write_fd= path.split(" ")[-1]
                
                read_node = "Pipe " + read_fd + " : read end from Pipe " + write_fd
                write_node = "Pipe " + write_fd + " : write end to Pipe " + read_fd
                
                # 不重複畫 edge
                if not self.isDuplicate :
                    if (self._file_node_map[write_node],  self._file_node_map[read_node], edge_name) not in self.edges:
                        self._connect_node(self._file_node_map[write_node] , self._file_node_map[read_node],  Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(self._file_node_map[write_node] , self._file_node_map[read_node],  Edge(edge_name, syscall['time']))
            if path[0] != "/":
                path = self.current_dir + path 
                
            ### hard filter the /lib/*、 /etc/ld.so ###
            if self.isHardFilter:
                
                for rule in self.hardRule:
                    isMatch = re.match(rule, path)
                    if isMatch:
                        return
            # if file appear in execve or currently not in execve
#             if (self._inside_execve and (path in self._execve_options)) or not self._inside_execve:
            # file node not exist
            if path not in self._file_node_map:
                child_node = Node(path, typ='f')
                self._file_node_map[path] = child_node
                self.graph[child_node] = []
                self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))

            # file node exist
            else:
                child_node = self._file_node_map[path]
                # if curent node has connected to file node open(), remove open edge
#                 replace_edge_name = ['open', 'connect']
#                 for exist_edge_name in replace_edge_name:
#                     edge = (self.current_node, child_node, exist_edge_name)
#                     if edge in self.edges:
#                         self._rm_connect(edge)

                # if has conected with read(), don't re-connect current node and child node
                if not self.isDuplicate :
                    if (child_node ,self.current_node, edge_name) not in self.edges:
                        self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))
                    
            
    def _write(self, syscall):
        info = sys_parser.parse(syscall)
        if 'fd' in info:
            fd = info['fd']
            path = self.file_table.get(fd)
        else:
            path = info['path']
        
        # fd may open in parent process
        if not path and not self._inside_execve:
            path = self._find_path_by_fd(fd, syscall['time'])
            
        ### inside_execve = True : Not draw the common file###
        elif path and self._inside_execve == True:

            isCommonFile = True
            for p in self.file_filter:
                if p in path:
                    isCommonFile = False
                    break

            if isCommonFile:
                return    
            
        # ignore paths
        if path in ignore_paths:
            return
            
        edge_name = 'write'
#         if not syscall['success']:
#             edge_name = f"write{syscall['return_msg']}"
        
        # if fd exist in fd table 
        if path:
           
            ### For pipe ###
            if("Pipe" in path):
                read_fd = path.split(" ")[-1]
                write_fd= path.split(" ")[1]
                
                read_node = "Pipe " + read_fd + " : read end from Pipe " + write_fd
                write_node = "Pipe " + write_fd + " : write end to Pipe " + read_fd
                
                # 不重複畫 edge
                if not self.isDuplicate :
                    if (self._file_node_map[write_node],  self._file_node_map[read_node], edge_name) not in self.edges:
                        self._connect_node(self._file_node_map[write_node] , self._file_node_map[read_node],  Edge(edge_name, syscall['time']))      
                else:
                    self._connect_node(self._file_node_map[write_node] , self._file_node_map[read_node],  Edge(edge_name, syscall['time'])) 
            if path[0] != "/":
                path = self.current_dir + path
                
            ### hard filter the /lib/*、 /etc/ld.so ###
            if self.isHardFilter:
                
                for rule in self.hardRule:
                    isMatch = re.match(rule, path)
                    if isMatch:
                        return
            # if file appear in execve or currently not in execve
#             if (self._inside_execve and (path in self._execve_options)) or not self._inside_execve:
            # file node not exist
            if path not in self._file_node_map:
                child_node = Node(path, typ='f')
                self._file_node_map[path] = child_node
                self.graph[child_node] = []
                self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))

            # file node exist
            else:
                child_node = self._file_node_map[path]

                # if curent node has connected to file node open(), remove open and connect edge
#                 replace_edge_name = ['open', 'connect']
#                 for exist_edge_name in replace_edge_name:
#                     edge = (self.current_node, child_node, exist_edge_name)
#                     if edge in self.edges:
#                         self._rm_connect(edge)

                # if has conected with write(), don't re-connect current node and child node
                if not self.isDuplicate :
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
           
    def _openn(self, syscall):
        info = sys_parser.parse(syscall)
        if not info:
            return
        path = info['path']
        if path[0] != "/":
            path = self.current_dir + path
            
        ### hard filter the /lib/*、 /etc/ld.so ###
        if self.isHardFilter:
            
            for rule in self.hardRule:
                isMatch = re.match(rule, path)
                if isMatch:
                    return
                
        edge_name = 'open'

#         if not syscall['success']:
#             edge_name = f"open{syscall['return_msg']}"

        # update fd table if open successfully
        if syscall['success']:
            self.file_table.add(syscall['return'], info['path'])
            #print(f"open {info['path']}: {self.file_table}")
        
        if path in ignore_paths:
            return
        
        # open and openat appear after execve in same strace.log
        if self._inside_execve:
            # find path that apeears in execve command option
            #print(path, self._execve_options, self._execve_options[0])
            if path in self._execve_options:
                self._connect_proc_file(path, edge_name, syscall['time']) 

        # not inside execve
        else:
            self._connect_proc_file(path, edge_name, syscall['time'])
        
    def _close(self, syscall):
        info = sys_parser.parse(syscall)
        fd = info['fd']
        
        # delete fd only if successfully close
        if syscall['success']:
            self.file_table.rm(fd)
        
    def _info(self, syscall):
        edge_name = 'read'
        path = syscall['name']
        if path[0] != "/":
            path = self.current_dir + path
            
        ### hard filter the /lib/*、 /etc/ld.so ###
        if self.isHardFilter:
            
            for rule in self.hardRule:
                isMatch = re.match(rule, path)
                if isMatch:
                    return
                
        if not self._inside_execve:
            self._connect_proc_file(path, edge_name, syscall['time'], from_proc = False, node_typ = 'c')
            
        ### inside_execve = True : Not draw the common file###
        elif self._inside_execve == True:
            if path not in self.file_filter: # if not the specific file that we select to remain, then do nothing
                return  
            else:
                self._connect_proc_file(path, edge_name, syscall['time'], from_proc = False, node_typ = 'c')
        
    def _socket(self, syscall):
        info = sys_parser.parse(syscall)
        fd = info['fd']
        
        if not syscall['success']:
            return
        
        # update fd table if create socket successfully
        if info['family'] not in ['AF_INET', 'PF_INET']:
            self.file_table.add(fd, "NOT_NET")
        else:
            self.file_table.add(syscall['return'])
        #print('socket: ', self.file_table)
        
    def _bind(self, syscall):
        info = sys_parser.parse(syscall)
        
        # ignore IPC usage
        if info['family'] not in ['AF_INET', 'PF_INET']:
            return
        
        fd = info['fd']
        path = info['addr']
        edge_name = 'bind'
        
        res = self.file_table.update(fd, path)
        if not res:
            print('socket fd not found.')
            raise KeyError
            
        self._connect_proc_file(path, edge_name, syscall['time'], node_typ = 'n')
        
    def _connect(self, syscall):
        info = sys_parser.parse(syscall)
        
        # ignore IPC usage
        if info['family'] not in ['AF_INET', 'PF_INET']:
            return
        
        fd = info['fd']
        path = info['addr']
        self.unique_ip.add(path)
        edge_name = 'connect'
        
        res = self.file_table.update(fd, path)
        if not res:
            print('socket fd not found.')
            raise KeyError
        
        # if file node not exist: create new node, else: connect current node to exist file node
        self._connect_proc_file(path, edge_name, syscall['time'], node_typ = 'n')
    
    def _recv(self, syscall):
        info = sys_parser.parse(syscall)
        fd = info['fd']
        edge_name = 'recv'

        if fd == "-1":
            node_name = "NO_SOCKET"
            if node_name not in self._file_node_map:
                child_node = Node(node_name, typ='n')
                self._file_node_map[node_name] = child_node
                self.graph[child_node] = []
                self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))
            else:
                child_node = self._file_node_map[node_name]
                if not self.isDuplicate :
                    if (child_node, self.current_node, edge_name) not in self.edges:
                        self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))      
            return 
        # socket error
        # if fd == '-1':
        #     # get ip addr from recvfrom
        #     if syscall['name'] == 'recvfrom':
        #         if 'addr' in info:
        #             path = info['addr']
        #             self.unique_ip.add(path)
        #         elif len(self.unique_ip) == 1:
        #             path = list(self.unique_ip)[0]
        #         else:
        #             return
                    
        #     else:
        #         return
            
        # socket create successfully
        if fd != '-1':
            # AF_UNIX socket
            if self.file_table.get(fd) == "NOT_NET":
                return
            
            # if malware use UDP, we need to map fd to ip addr through sendto
            if syscall['name'] == 'recvfrom' and not self.file_table.get(fd):
                if 'addr' in info:
                    path = info['addr']

                elif len(self.unique_ip) == 1:
                    path = list(self.unique_ip)[0]

                self.file_table.update(fd, path)
                self.unique_ip.add(path)       
                
            path = self.file_table.get(fd)
            # created in parent process, find it
            if not path:
                path = self._find_path_by_fd(fd, syscall['time'])
        
        # file node not exist
        if path not in self._file_node_map:
            child_node = Node(path, typ='n')
            self._file_node_map[path] = child_node
            self.graph[child_node] = []
            self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))

        # file node exist
        else:
            child_node = self._file_node_map[path]
            # if curent node has connected to file node open(), remove open edge
#             replace_edge_name = ['connect']
#             for exist_edge_name in replace_edge_name:
#                 edge = (self.current_node, child_node, exist_edge_name)
#                 if edge in self.edges:
#                     self._rm_connect(edge)

            # if has conected with recv(), don't re-connect current node and child node
            if not self.isDuplicate :
                if (child_node, self.current_node, edge_name) not in self.edges:
                    self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))
            else:
                self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))
                

                        
    def _send(self, syscall):
        info = sys_parser.parse(syscall)
        fd = info['fd']
        edge_name = 'send'

        if fd == "-1":
            node_name = "NO_SOCKET"
            if node_name not in self._file_node_map:
                child_node = Node(node_name, typ='n')
                self._file_node_map[node_name] = child_node
                self.graph[child_node] = []
                self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
            else:
                child_node = self._file_node_map[node_name]
                if not self.isDuplicate :
                    if (child_node, self.current_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                else:
                    self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))

            return       
        # socket create unsuccessfully
        # if fd == '-1':
        #     if syscall['name'] == 'sendto':
        #         if 'addr' in info:
        #             path = info['addr']
        #             self.unique_ip.add(path)
        #         elif len(self.unique_ip) == 1:
        #             path = list(self.unique_ip)[0]
        #         else:
        #             return
                    
        #     else:
        #         return
            
        # socket create successfully
        if fd != '-1':
            # AF_UNIX socket
            if self.file_table.get(fd) == "NOT_NET":
                return
            
            # if malware use UDP, we need to map fd to ip addr through sendto
            if syscall['name'] == 'sendto' and not self.file_table.get(fd):
                if 'addr' in info:
                    path = info['addr']

                elif len(self.unique_ip) == 1:
                    path = list(self.unique_ip)[0]

                self.file_table.update(fd, path)
                self.unique_ip.add(path)       
                
            path = self.file_table.get(fd)
            # created in parent process, find it
            if not path:
                path = self._find_path_by_fd(fd, syscall['time'])
        
            
        # file node not exist
        if path not in self._file_node_map:
            child_node = Node(path, typ='n')
            self._file_node_map[path] = child_node
            self.graph[child_node] = []
            self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))

        # file node exist
        else:
            child_node = self._file_node_map[path]
            # if curent node has connected to file node open(), remove open edge
#             replace_edge_name = ['connect', 'getsockopt']
#             for exist_edge_name in replace_edge_name:
#                 edge = (self.current_node, child_node, exist_edge_name)
#                 if edge in self.edges:
#                     self._rm_connect(edge)

            # if has conected with send(), don't re-connect current node and child node
            if not self.isDuplicate :
                if (self.current_node, child_node, edge_name) not in self.edges:
                    self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
            else:
                self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
                
                

                
    def _ioctl(self, syscall):
        info = sys_parser.parse(syscall)
        if info['req'] != 'SIOCGIFADDR':
            return
        
        edge_name = 'read'
        path = info['dev']
        
        self._connect_proc_file(path, edge_name, syscall['time'], from_proc = False, node_typ = 'n')
        
    
    def _rm(self, syscall):
        info = sys_parser.parse(syscall)
        path = info['path']
        
        edge_name = 'rm'
        self._connect_proc_file(path, edge_name, syscall['time'])
        
    def _mkdir(self, syscall):
        info = sys_parser.parse(syscall)
        path = info['path']
        
        edge_name = 'mkdir'
        self._connect_proc_file(path, edge_name, syscall['time'])
        
    def _link(self, syscall):
        info = sys_parser.parse(syscall)
        t = info['target']
        l = info['link']
        
        self._connect_proc_file(t, 'read', syscall['time'], from_proc = False)
        self._connect_proc_file(l, 'write', syscall['time'])
        
    
    def _kill(self, syscall):
        info = sys_parser.parse(syscall)
        pid = info['pid']
        
        self._connect_proc_file(pid, 'kill', syscall['time'], node_typ = 'p')
        
    def _ptrace(self, syscall):
        info = sys_parser.parse(syscall)
        req = info['req'].lower()
        if 'pid' in info:
            self._connect_proc_file(info['pid'], req, syscall['time'], node_typ = 'p')
        else:
            self._connect_proc_file(self.current_node.name, req, syscall['time'], node_typ = 'p')
        
    def _syscall_handler(self, syscall):
        name = syscall['name']
        
        # child process creation
        if name in process_creation:
            self._syscall_handler_table['process'](syscall)
            self.trigger_lines += 1
        
        # file open
        elif name in open_file:
            self._syscall_handler_table['open'](syscall)
            self.trigger_lines += 1
            
        elif name in write_file:
            self._syscall_handler_table['write'](syscall)
            self.trigger_lines += 1
        
        elif name in info:
            self._syscall_handler_table['info'](syscall)
            self.trigger_lines += 1
            
        elif name in send:
            self._syscall_handler_table['send'](syscall)
            self.trigger_lines += 1
        
        elif name in recv:
            self._syscall_handler_table['recv'](syscall)
            self.trigger_lines += 1
            
        elif name in remove:
            self._syscall_handler_table['rm'](syscall)
            self.trigger_lines += 1
            
        elif name in link:
            self._syscall_handler_table['link'](syscall)
            self.trigger_lines += 1
        
        elif name in self._syscall_handler_table:
            self._syscall_handler_table[name](syscall)
            self.trigger_lines += 1

        elif name in self.added_handler_table:
            self._added_handler(syscall)
        #     self.added_handler_table[name](syscall)
        #     self.trigger_lines += 1
    
    # main method to create attck graph
    def create(self):
        total_line = 0
        for idx, trace in enumerate(self.traces):
            #print(trace)
            proc_id = re.search(RE_PID, trace).group(1)
            self.proc_id = proc_id
            # init root node
            if idx == 0:
                self.proc_node_map[proc_id] = Node('malware')
            
            # current process node for this trace
            self.current_node = self.proc_node_map[proc_id]
            self.graph[self.current_node] = []
            self._inside_execve = False
            self.exec = False
            
            first_line = True
            
            # counter = 0
            with open(trace, 'r') as f:
                for line in f:
                    total_line += 1
                    if idx == 0 and first_line:
                        first_line = False
                        continue
                    line = line.strip()
                    call = parse_line(line)
                    
                    if not call:
                        continue

                    if call['type'] == 'sys':
                        # sys_ignore = ['open', 'openat', 'read']
#                         sys_ignore = ['read']
#                         if(call['name'] == 'gettimeofday'):
#                             print("Call:", call)
#                             print("Args:", call['args'], type(call['args']))
#                             print("Args split:", call['args'].split(",") )
#                             print("Parse :", sys_parser.parse(call))
#                             break
                        
                        
                        self._syscall_handler(call)
                         #myprint(call, 'socket')
            

        self.traces_lines = total_line
        # print("Total trace lines:", self.traces_lines)

        ### set of object ###
        for step in self.step_list:
            from_node = step[0]
            to_node = step[1]
            edge_name = step[2]
            
            reverse_edge = ["read", "recv"] 
            if to_node.name not in self.set_of_object and edge_name not in reverse_edge:
                trans_dict = {"f":"File", "c":"File", "pipe":"Process", "p":"Process", "n":"Net", "m_addr":"Memory", "else":"Other"}

                self.set_of_object[to_node.name] = trans_dict[to_node.type]
                self.set_of_object_summary[trans_dict[to_node.type]] += 1
                self.set_of_object_summary_list[trans_dict[to_node.type]].append(to_node.name)

            if edge_name in reverse_edge:
                if from_node.name not in self.set_of_object:
                    trans_dict = {"f":"File", "c":"File", "pipe":"Process", "p":"Process", "n":"Net", "m_addr":"Memory", "else":"Other"}

                    self.set_of_object[from_node.name] = trans_dict[from_node.type]
                    self.set_of_object_summary[trans_dict[from_node.type]] += 1
                    self.set_of_object_summary_list[trans_dict[from_node.type]].append(from_node.name)

    def sort_edges(self, edges, rm_nodes):
        if len(rm_nodes) != 0:
            edges = [edge for pair, edge in edges.items() if pair[0] not in rm_nodes and pair[1] not in rm_nodes]
        else:
            edges = list(edges.values())
            
        edges.sort(key = lambda edge: datetime.strptime(edge.timestamp, STRACE_TIME_FORMAT))
        self._edges_sort_map = {}
        
        for idx, edge in enumerate(edges):
            self._edges_sort_map[edge] = str(idx + 1)
            
    def node_reduction(self, depth):
        file_counter = {}
        ip_counter = {"External_IP": 0, "Local_IP": 0}
        
        file_set = set()
        ip_set = set()
        
        pub_ip_node = Node('External_IP', typ = 'n')
        pub_ip_node.color = COMMAND_CONTROL_COLOR
        pub_ip_node.tactic ='Command & Control', 
        pub_ip_node.technique = "Command & Control"
        pub_ip_node.id = "C&C"
        
        pri_ip_node = Node('Local_IP', typ = 'n')
    
        reduced_file_map = {}
        nodes = set()
        
        # create another edges for visualization
        node_pairs = []
        edge_vals = []
        for pair, edge in self.edges.items():
            node_pairs.append(pair)
            edge_vals.append(edge)
            
        edges = {}
        for pair_idx, pair in enumerate(node_pairs):
            new_pair = list(pair)
            for idx, node in enumerate(new_pair[:2]):
                # if node is a file or ip addr
                if node.type in ['f', 'n']:
                    if node.name.startswith('8.8.8.8'):
                        nodes.add(node)
                        continue
                        
                    if re.search(ENDPOINT_REGEX, node.name):
                        if re.search(PRIVATE_IP_REGEX, node.name):
                            if node.name not in ip_set:
                                ip_counter['Local_IP'] += 1
                                ip_set.add(node.name)
                                
                            new_pair[idx] = pri_ip_node
                            nodes.add(pri_ip_node)
                        else:
                            if node.name not in ip_set:
                                ip_counter['External_IP'] += 1
                                ip_set.add(node.name)
                                
                            new_pair[idx] = pub_ip_node
                            nodes.add(pub_ip_node)

                    # file path
                    else:
                        paths = node.name.split('/')
                        
                        if len(paths) <= depth:
                            name = "/".join(paths)
                        else:
                            name = "/".join(paths[:depth + 1])
                            

                        if name not in reduced_file_map:
                            if name == "NO_SOCKET" or name[0:3] == "NIC":
                                file_node = Node(name, typ = 'n')
                            else:
                                file_node = Node(name, typ = 'f')
                            file_node.tactic = node.tactic
                            file_node.technique = node.technique
                            file_node.color = node.color
                            file_node.id = node.id
                            
                            reduced_file_map[name] = file_node
                            file_counter[name] = 1
                            file_set.add(node.name)
                            
                        else:
                            file_node = reduced_file_map[name]
                            
                            if node.name not in file_set:
                                file_set.add(node.name)
                                file_counter[name] += 1
                            
                        nodes.add(file_node)
                        new_pair[idx] = file_node
                        
                    
                # if node is process or command       
                else:
                    nodes.add(node)
                    
            # save new pair
            new_pair = tuple(new_pair)
            edges[new_pair] = edge_vals[pair_idx]
            
        # label count number on reduction node
        for node in nodes:
            if node.type == 'n' and node.name in ip_counter:
                count = ip_counter[node.name]
                if count > 1:
                    node.name = node.name + f" ({count})"
            elif node.type == 'f' and node.name in file_counter:
                count = file_counter[node.name]
                if count > 1:
                    node.name = node.name + f" ({count})"
                
            
        return nodes, edges
    
    def is_process_node(self, node):
        return node.type == 'p' and re.search('^[0-9]*$', node.name)
                                  
    def draw(self, showall = True, depth = 3):
        # Create Digraph object
        display_threshold = 30
        # twopi
        dot = Digraph(engine='dot', format='pdf')
        #dot.attr(size='35,50')
        #dot.graph_attr['overlap'] =  "false"
        #dot.graph_attr['splines'] = "true"
        
        node_table = {}
        nodes = list(self.graph.keys())
        edges = dict(self.edges)
        
        self.all_nodes_num = len(nodes)
        print('Node before reduction: ', self.all_nodes_num)
        self.color_nodes_num = 0
        
        
        # nodes to be removed
        rm_nodes = set()
        
        # remove node that have only on edge clone from parent
        if not showall:
            # node have no child node
            for node in nodes:
                # if a node have no child node
                if self.is_process_node(node):
                    if len(self.graph[node]) == 0:
                        rm_nodes.add(node)
                    
            for node in nodes:
                if len(self.graph[node]) == 1 and self.graph[node][0] in rm_nodes:
                    rm_nodes.add(node)

            # node in rm_nodes that have only one parent node which its edge in process_creation
            for pair, edge in edges.items():
                from_node, to_node, _ = pair
                if to_node in rm_nodes and edge.name not in process_creation:
                    rm_nodes.remove(to_node)
            
            for node in rm_nodes:
                print(f'Remove Node: {node.name}')
        
        # print(self.all_nodes_num - len(rm_nodes))
        if (self.all_nodes_num - len(rm_nodes)) > display_threshold and not showall:
            nodes, edges = self.node_reduction(depth)
            
        
        # visulization node counting
        self.viz_nodes_num = len(nodes) - len(rm_nodes)
        print('Nodes after reduction: ', self.viz_nodes_num)
        # sort edge
        self.sort_edges(edges, rm_nodes)
        
        # draw node
        for idx, node in enumerate(nodes):
            idx = str(idx)
            
            if not showall and node in rm_nodes:
                continue
            
            
            node_name = node.name
            if node.technique:
                 node_name += f'\n({node.id})'
            
            if node.color:
                self.color_nodes_num += 1

            if node.type == 'n':
                dot.node(idx, node_name, shape='diamond', color = node.color, style='filled')
            elif node.type in ['f', 'c']:
                dot.node(idx, node_name, shape='rectangle', color = node.color, style='filled')
            # elif node.type == 'n':
            #     dot.node(idx, node_name, shape='diamond', color = node.color, style='filled')
            elif node.type == 'm_addr':
                dot.node(idx, node_name, shape='pentagon', color = node.color, style='filled')
            elif node.type == 'pipe':
                dot.node(idx, node_name, shape='cylinder', color = node.color, style='filled')
            elif node.type == 'else':
                dot.node(idx, node_name, shape='tab', color = node.color, style='filled')
            else:
                dot.node(idx, node_name, color = node.color, style='filled')
                
            node_table[node] = idx
        
        self.node_seq = []
        
        # draw edge
        for pair, edge in edges.items():
            from_node, to_node, _ = pair
            
            if not showall and (from_node in rm_nodes or to_node in rm_nodes):
                continue
            
            self.node_seq.append([self._edges_sort_map[edge], from_node, to_node, edge])
            
            from_node = node_table[from_node]
            to_node = node_table[to_node]
            
            edge_name = self._edges_sort_map[edge] + '. ' + edge.name
            dot.edge(from_node, to_node, edge_name, color = edge.color)
        
        # sort node sequence
        self.node_seq = sorted(self.node_seq, key=lambda x: int(x[0]))
        
        return dot

### MITRE Mapping Rules ###
DISCOVERY_COLOR = '#FDE74C'
PERSISTENCE_COLOR = '#9BC53D'
EXECUTION_COLOR = '#26C485'
COMMAND_CONTROL_COLOR = '#CC5A71'

DISCOVERY = [{
    "tactic": "Discovery",
    "technique": "System Information Discovery",
    "id": "T1082",
    "file_edges": ['open', 'read'],
    "command_edges": ['exec'],
    "commands": ['lspci', 'dmidecode', 'lscpu', 'lsmod', 'hostname'],
    "files": ['/etc/lsb-release', '/etc/redhat-release', '/etc/issue', 'sysinfo', 'uname', 
              '/proc/cpuinfo', '/proc/meminfo', '/proc/stat', '/proc/version', '/proc/sys/kernel/version', 
              '/proc/sys/kernel/ngroups_max', '/sys/'],
    "color": DISCOVERY_COLOR
    
}, {
    "tactic": "Discovery",
    "technique": "System Network Connection Discovery",
    "id": 'T1049',
    "file_edges": ['open', 'read', 'connect'],
    "command_edges": ['exec'],
    "commands": ['netstat', 'lsof', 'who', 'w'],
    "files": ['/proc/net/dev', '/proc/net/tcp', '/proc/net/route', '8\.8\.8\.8'],
    "color": DISCOVERY_COLOR
}, {
    "tactic": "Discovery",
    "technique": "System Network Configuration Discovery",
    "id": "T1016",
    "file_edges": ['open', 'read'],
    "command_edges": ['exec'],
    "commands": ['arp', 'ifconfig', 'ip'],
    "files": ['/proc/net/arp', '/proc/net/unix', '/etc/nsswitch.conf', '/etc/resolv.conf',
              '/etc/host', 'eth'],
    "color": DISCOVERY_COLOR
}]

PERSISTENCE = [{
    "tactic": "Persistence",
    "technique": "Local Job Scheduling",
    "id": "T1168",
    "file_edges": ['open', 'write'],
    "command_edges": ['exec', 'clone', 'fork', 'vfork'],
    "commands": ['crontab'],
    "files": ['/etc/rc', '/etc/init', '/etc/cron', '/var/spool/cron'],
    'color': PERSISTENCE_COLOR
}]

EXECUTION = [{
    "tactic": "Execution",
    "technique": "Command-Line Interface",
    "id": 'T1059',
    "file_edges": [],
    "command_edges": ['clone', 'exec', 'fork', 'vfork'],
    "commands": ['sh', 'bash', 'dash', 'rbash'],
    "files": [],
    "color": EXECUTION_COLOR
}]

COMMAND_CONTROL = [{
    "tactic": "Command & Control",
    "technique": "Command & Control",
    "id": "C&C",
    "file_edges": [],
    "command_edges": ['exec', 'clone', 'fork', 'vfork'],
    "commands": ['nc', 'wget', 'curl'],
    "files": [],
    "color": COMMAND_CONTROL_COLOR
}]


### Tactic & Technique Graph Generation ###

# Generation of TT Graph
class TTPLabeler:
    def __init__(self, attack_graph):
        self.graph = attack_graph
        
    def set_technique(self, node, edge, rule):
        #print(edge.name, node.name)
        node.technique = rule['technique']
        node.tactic = rule['tactic']
        node.color = rule['color']
        node.id = rule['id']
        
        edge.technique = rule['technique']
        edge.tactic = rule['tactic']
        edge.color = rule['color']
    
    def mapper(self, rules):
        for rule in rules:            
            # map files
            if self.edge.name in rule['file_edges']:
                for node in self.nodes:
                    if node.type in ['f', 'n', 'c']:                                
                        for file in rule['files']:
                            if re.search(file, node.name):
                                self.set_technique(node, self.edge, rule)
                                return
            
            
            # map commands
            if self.edge.name in rule['command_edges']:
                for node in self.nodes:
                    if node.type == 'p':
                        for command in rule['commands']:
                            if re.search(f'^{command}$', node.name):
                                self.set_technique(node, self.edge, rule)
                                return
                            
    
    def execution_mapper(self):
        self.mapper(EXECUTION)
        
    def discovery_mapper(self):
        self.mapper(DISCOVERY)
    
    def persistence_mapper(self):
        self.mapper(PERSISTENCE)
        
    def command_control_mapper(self):
        self.mapper(COMMAND_CONTROL)
        
        # label external ip connection
        for node in self.nodes:
            if node.type != 'n':
                continue
            if node.name.startswith('8.8.8.8'):
                continue
                
            if self.edge.name not in ['send', 'recv', 'connect', 'read', 'write']:
                continue
                
            if re.search(ENDPOINT_REGEX, node.name) and not re.search(PRIVATE_IP_REGEX, node.name):
                self.set_technique(node, self.edge, COMMAND_CONTROL[0])
    
    def fit(self):
        edges = self.graph.edges
        for nodes, edge in edges.items():
            #print(nodes[0].name, nodes[1].name)
            self.nodes = nodes[:2]
            self.edge = edge
            
            # map each tactic
            self.discovery_mapper()
            self.persistence_mapper()
            self.execution_mapper()
            self.command_control_mapper()

def build(family_dir: str, sample_dir: str, output_filename: str='', save_file: bool=True, draw: bool=False):
    ''' build ASG&TTG. Read from `trace/family/sample/`, store output image at `output/family/sample.svg`. Return `AttackGraph`,`graphviz.graphs.Digraph`.'''
    path = f'../C ASG/trace/{family_dir}/{sample_dir}' # trace log folder for a sample
    if not os.path.isdir(path):
        print(f'  error, path not extst: {path}')
        return None
    # print('  path:', path)
    output_path = path.replace('trace', 'output')
    if len(output_filename):
        output_path = output_path.replace(sample_dir, output_filename)

    # Create Attack Scenario Graph
    graph = AttackGraph(path)
    graph.create()

    return graph

# unit test
# graph = build('dofloo', '0046a78514a658b9b7a4e29e8581f85b.bin')
# print("set of object:", graph.set_of_object)