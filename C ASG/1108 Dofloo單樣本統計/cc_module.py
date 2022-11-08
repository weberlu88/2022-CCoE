


# !pip install graphviz

import glob
import re
import subprocess
import os
from datetime import datetime
from graphviz import Digraph


# # Global Variables

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
write_file = ['write', 'rename']
info = ['uname', 'sysinfo']
send = ['send', 'sendto', 'sendmsg']
recv = ['recv', 'recvfrom', 'recvmsg']
remove = ['unlink', 'unlinkat', 'rmdir']
link = ['symlink', 'symlinkat', 'link', 'linkat']

#### ignore path ####
ignore_paths = ['/dev/null', 'stdout', 'stderr']

# # Trace Parser

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
    print(path)
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

# # File Descriptor Handler

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

# # System Call Parser

class SyscallParser:
    def __init__(self):        
        self.parse_handler = {
            # execve
            'execve': self.execve,
            # openFile
            'open': self.openn,
            'openat': self.openat,
            # read
            'read': self.read,
            # close
            'close': self.close,
            # writeFile
            'write': self.write,
            'rename': self.rename,
            # socket
            'socket': self.socket,
            # connect
            'connect': self.connect,
            # send
            'send': self.send,
            'sendto': self.sendto,
            'sendmsg': self.sendmsg,
            # recv
            'recv': self.recv,
            'recvfrom': self.recvfrom,
            'recvmsg': self.recvmsg,
            # ioctl
            'ioctl': self.ioctl,
            # remove
            'unlink': self.unlink,
            'unlinkat': self.unlinkat,
            'rmdir': self.rmdir,
            # bind
            'bind': self.bind,
            # mkdir
            'mkdir': self.mkdir,
            # link
            'symlink': self.symlink,
            'symlinkat': self.symlinkat,
            'link': self.link,
            'linkat': self.linkat,
            # kill
            'kill': self.kill,
            # ptrace
            'ptrace': self.ptrace
        }
        
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
    
    # issue: openat(int fd, const char *path, int oflag, ...)
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
        info['path'] = re.search('\"(.*)\"', args[1]).group(1)
        
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
            info['dev'] = re.search(RE_IOCTL_NAME, self.syscall['args']).group(1)
            
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

# # Attack Scenario Graph Main Class Definition

class AttackGraph:
    def __init__(self, path):
        self.malware_hash = path.split('/')[-1]
        self.traces = sorted(glob.glob(path + '/strace*'))
        self.graph = {}
        self.edges = {}
        
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
        
        self._path = path
        
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
            if (from_node, to_node, edge_name) not in self.edges:
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
                        elif name == 'socket':
                            info = sys_parser.parse(syscall)
                            # update fd table if create socket successfully
                            if info['family'] not in ['AF_INET', 'PF_INET']:
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

        if self._inside_execve:
            edge = Edge('exec', syscall['time'])
        else:
            edge = Edge(syscall['name'], syscall['time'])

        self._connect_node(self.current_node, child_node, edge)
    
    def _execve(self, syscall):
        self._inside_execve = True
            
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
            
    def _read(self, syscall):
        info = sys_parser.parse(syscall)
        fd = info['fd']
        path = self.file_table.get(fd)
        
        # fd may open in parent process
        if not path and not self._inside_execve:
            path = self._find_path_by_fd(fd, syscall['time'])
            
        # ignore paths
        if path in ignore_paths:
            return
        
        edge_name = 'read'
#         if not syscall['success']:
#             edge_name = f"read{syscall['return_msg']}"
        
        # if fd exist in fd table 
        if path:
            # if file appear in execve or currently not in execve
            if (self._inside_execve and (path in self._execve_options)) or not self._inside_execve:
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
                    replace_edge_name = ['open', 'connect']
                    for exist_edge_name in replace_edge_name:
                        edge = (self.current_node, child_node, exist_edge_name)
                        if edge in self.edges:
                            self._rm_connect(edge)

                    # if has conected with read(), don't re-connect current node and child node
                    if (child_node ,self.current_node, edge_name) not in self.edges:
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
        
        # ignore paths
        if path in ignore_paths:
            return
            
        edge_name = 'write'
#         if not syscall['success']:
#             edge_name = f"write{syscall['return_msg']}"
        
        # if fd exist in fd table 
        if path:
            # if file appear in execve or currently not in execve
            if (self._inside_execve and (path in self._execve_options)) or not self._inside_execve:
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
                    replace_edge_name = ['open', 'connect']
                    for exist_edge_name in replace_edge_name:
                        edge = (self.current_node, child_node, exist_edge_name)
                        if edge in self.edges:
                            self._rm_connect(edge)
                    
                    # if has conected with write(), don't re-connect current node and child node
                    if (self.current_node, child_node, edge_name) not in self.edges:
                        self._connect_node(self.current_node, child_node, Edge(edge_name, syscall['time']))
        
           
    def _openn(self, syscall):
        info = sys_parser.parse(syscall)
        if not info:
            return
        path = info['path']
        
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
        
        if not self._inside_execve:
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
        
        # socket error
        if fd == '-1':
            # get ip addr from recvfrom
            if syscall['name'] == 'recvfrom':
                if 'addr' in info:
                    path = info['addr']
                    self.unique_ip.add(path)
                elif len(self.unique_ip) == 1:
                    path = list(self.unique_ip)[0]
                else:
                    return
                    
            else:
                return
            
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
            replace_edge_name = ['connect']
            for exist_edge_name in replace_edge_name:
                edge = (self.current_node, child_node, exist_edge_name)
                if edge in self.edges:
                    self._rm_connect(edge)

            # if has conected with recv(), don't re-connect current node and child node
            if (child_node, self.current_node, edge_name) not in self.edges:
                self._connect_node(child_node, self.current_node, Edge(edge_name, syscall['time']))
        
    def _send(self, syscall):
        info = sys_parser.parse(syscall)
        fd = info['fd']
        edge_name = 'send'
        
        # socket create unsuccessfully
        if fd == '-1':
            if syscall['name'] == 'sendto':
                if 'addr' in info:
                    path = info['addr']
                    self.unique_ip.add(path)
                elif len(self.unique_ip) == 1:
                    path = list(self.unique_ip)[0]
                else:
                    return
                    
            else:
                return
            
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
            replace_edge_name = ['connect']
            for exist_edge_name in replace_edge_name:
                edge = (self.current_node, child_node, exist_edge_name)
                if edge in self.edges:
                    self._rm_connect(edge)

            # if has conected with send(), don't re-connect current node and child node
            if (self.current_node, child_node, edge_name) not in self.edges:
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
        
        # file open
        elif name in open_file:
            self._syscall_handler_table['open'](syscall)
            
        elif name in write_file:
            self._syscall_handler_table['write'](syscall)
        
        elif name in info:
            self._syscall_handler_table['info'](syscall)
            
        elif name in send:
            self._syscall_handler_table['send'](syscall)
        
        elif name in recv:
            self._syscall_handler_table['recv'](syscall)
            
        elif name in remove:
            self._syscall_handler_table['rm'](syscall)
            
        elif name in link:
            self._syscall_handler_table['link'](syscall)
        
        elif name in self._syscall_handler_table:
            self._syscall_handler_table[name](syscall)
    
    # main method to create attck graph
    def create(self):
        for idx, trace in enumerate(self.traces):
#             print(trace)
            proc_id = re.search(RE_PID, trace).group(1)
            # init root node
            if idx == 0:
                self.proc_node_map[proc_id] = Node('malware')
            
            # current process node for this trace
            self.current_node = self.proc_node_map[proc_id]
            self.graph[self.current_node] = []
            self._inside_execve = False
            
            first_line = True
            with open(trace, 'r') as f:
                for line in f:
                    if line.find('execve(') != -1:
                        aaaa = 1
                    if idx == 0 and first_line:
                        first_line = False
                        continue
                    line = line.strip()
                    call = parse_line(line)
                    
                    if not call:
                        continue

                    if call['type'] == 'sys':
                        self._syscall_handler(call)
                         #myprint(call, 'socket')

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
        # print('Node before reduction: ', self.all_nodes_num) # 先註解掉
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
        
        # print(self.all_nodes_num - len(rm_nodes)) # 先註解掉
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
                
            if node.type in ['f', 'c']:
                dot.node(idx, node_name, shape='rectangle', color = node.color, style='filled')
            elif node.type == 'n':
                dot.node(idx, node_name, shape='diamond', color = node.color, style='filled')
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

# # MITRE Mapping Rules

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

# # Tactic & Technique Graph Generation

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

# %% [markdown]
# # Generation of AS Graph & TT Graph

# %% [markdown]
# path: 設為動態側錄系統產生的惡意程式 traces 的路徑

# %%
# path = './root_real_network/Backdoor/Dofloo/fb3cf2464f43906cb96523752d74e5ad8e4eccf8ab74890e51fe24266921ef1c'
# path = './trace/Xorddos/7eba17d4ea5615e239c00e47d182e08a.bin'

# # %%
# # Create Attack Scenario Graph
# graph = AttackGraph(path)
# graph.create()

# # Create TT Graph based on AS Graph
# mapper = TTPLabeler(graph)
# mapper.fit()

# # Create Visualization Instance
# g = graph.draw(True)

# # save graph as svg file
# g.render(output_path, format='svg') #  view=True

def build(family_dir: str, sample_dir: str, output_filename: str='', save_file: bool=True):
    ''' build ASG&TTG. Read from `trace/family/sample/`, store output image at `output/family/sample.svg`. Return `AttackGraph`,`graphviz.graphs.Digraph`.'''
    path = f'../trace/{family_dir}/{sample_dir}' # trace log folder for a sample
    if not os.path.isdir(path):
        print(f'error, path not extst: {path}')
        return None, None
    print('path:', path)
    output_path = path.replace('trace', 'output')
    if len(output_filename):
        output_path = output_path.replace(sample_dir, output_filename)

    # Create Attack Scenario Graph
    graph = AttackGraph(path)
    graph.create()

    # Create TT Graph based on AS Graph
    mapper = TTPLabeler(graph)
    mapper.fit()

    # Create Visualization Instance
    g = graph.draw(True)

    # save graph as svg file
    if save_file:
        g.render(output_path, format='svg') #  view=True
    return graph, g

# unit test
# build('Dofloo-all', '9a37fcc7eab08d59532bc5c66390bc30.bin')
