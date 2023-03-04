# import re
# import os
# from os import listdir
# from os.path import isfile, join
# from pathlib import Path
# import pandas as pd
from typing import Callable, Dict, List, get_type_hints
import spacy
from spacy import displacy
from spacy.lang.char_classes import ALPHA, ALPHA_LOWER, ALPHA_UPPER, HYPHENS
from spacy.lang.char_classes import CONCAT_QUOTES, LIST_ELLIPSES, LIST_ICONS
from spacy.util import compile_infix_regex
import os, psutil

# https://stackoverflow.com/questions/66636097/prevent-spacy-tokenizer-from-splitting-on-specific-character
def prepare_nlp() -> Callable:
    nlp = spacy.load("en_core_web_sm")
    text = "Get 10ct/liter off when using our App"
    # Modify tokenizer infix patterns
    infixes = (
        LIST_ELLIPSES
        + LIST_ICONS
        + [
            r"(?<=[0-9])[+\-\*^](?=[0-9-])",
            r"(?<=[{al}{q}])\.(?=[{au}{q}])".format(
                al=ALPHA_LOWER, au=ALPHA_UPPER, q=CONCAT_QUOTES
            ),
            r"(?<=[{a}]),(?=[{a}])".format(a=ALPHA),
            r"(?<=[{a}])(?:{h})(?=[{a}])".format(a=ALPHA, h=HYPHENS),
            #r"(?<=[{a}0-9])[:<>=/](?=[{a}])".format(a=ALPHA),
            r"(?<=[{a}0-9])[:<>=](?=[{a}])".format(a=ALPHA),
        ]
    )
    infix_re = compile_infix_regex(infixes)
    nlp.tokenizer.infix_finditer = infix_re.finditer

    return nlp

# a global funciton
customized_nlp = prepare_nlp()

def find_verb_of_vocab(sentence: str, target_word: str, lemma=True):
    'Pass a sentence and a target_word, return the verb operates on the target_word or None. Lemmatization applied at default.'
    doc = customized_nlp(sentence)
    # find the target_word element (excat match)
    target_elem = None
    for i,token in enumerate(doc):
        if token.text == target_word:
            target_elem = token
    if target_elem is None:
        return None
    # find the verb parent of the target_word element
    token = target_elem
    while token.head != token:
        token = token.head
        # verb found
        if token.tag_.startswith('VB'):
            if lemma:
                return token.lemma_
            return token.text
    return None

def syscall_verb_analysis(syscall: str, en_verb: str) -> tuple[bool, int]:
    '''Pass a syscall and a verb, return they are similiar or not and the weight (2 or 1).
    @return similiarity: boolean, weight: int'''
    return 

from enum import Enum

class OperationMode(Enum):
    FILE_READ_CLOSE = 0
    FILE_CREATE_OPEN = 1
    FILE_UPDATE = 2
    FILE_DELETE = 3
    PROCESS_EXE = 4
    PROCESS_KILL = 5
    PROCESS_Other = 6
    DEVICE = 7
    INFO_GET = 8
    INFO_SET = 9
    COMM_CONNECT = 10
    COMM_TRANSMIT = 11

class OperationEvaluator:
    '''
    Prepare following fields when init:
    @self.mode_verb_convertor
    @self.syscall_convertor\n
    You shold call the resolve() func instead of accessing these fields.
    '''
    def __init__(self) -> None:
        # mode has en_verbs
        self.mode_verb_convertor = {
            OperationMode.FILE_READ_CLOSE: "read、get、gather、check、find、check、close、fetch、look、see、use、extract、wait、select",
            OperationMode.FILE_CREATE_OPEN: "create、open、add、drop、mount",
            OperationMode.FILE_UPDATE: "update、format、modify、write、overwrite、set、change、rename",
            OperationMode.FILE_DELETE: "delete、remove、drop",
            OperationMode.PROCESS_EXE: "execute、use、call、spawn、fork、perform、install、add、start",
            OperationMode.PROCESS_KILL: "kill",
            OperationMode.PROCESS_Other: "map、wait、sleep、trace、exit、end、break",
            OperationMode.DEVICE: "control、send",
            OperationMode.INFO_GET: "set、configure、assign",
            OperationMode.INFO_SET: "get、look、check、find",
            OperationMode.COMM_CONNECT: "send、receive、communicate、transfer、create、wget、download",
            OperationMode.COMM_TRANSMIT: "connect、bind、get、hook",
        }
        for opMode, string in self.mode_verb_convertor.items():
            self.mode_verb_convertor[opMode] = string.split('、')
        # syscall belongs to mode
        syscall_mode_table = {
            OperationMode.FILE_READ_CLOSE: "linkat()、statfs()、stat()、lseek()、readlink()、stat64()、access()、poll()、ppoll()、getcwd()、read()、fstat64()、dup()、dup2()、fstat()、fcntl64()、symlinkat()、umask()、newfstatat()、getdents()、fcntl()、_newselect()、select()、chdir()、close()",
            OperationMode.FILE_CREATE_OPEN: "mkdir()、open()、openat()、mmap()、mmap2()",
            OperationMode.FILE_UPDATE: "write()、rename()、fchmod()、chown()、fchown()、lchown()、link()、lstat()、symlink()",
            OperationMode.FILE_DELETE: "rm()、rmdir()、munmap()、unlink()、unlinkat()、remove()",
            OperationMode.PROCESS_EXE: "execve()、clone()、fork()、vfork()",
            OperationMode.PROCESS_KILL: "kill()",
            OperationMode.PROCESS_Other: "mremap()、mprotect()、set_tid_address()、arch_prctl()、set_thread_area()、waitpid()、nanosleep()、ptrace()、set_robust_list()、wait4()、futex()、exit_group()、brk()",
            OperationMode.DEVICE: "ioctl()",
            OperationMode.INFO_GET: "setsid()",
            OperationMode.INFO_SET: "getppid()、getgid()、shmdt()、getegid()、geteuid()、prlimit64()、shmat()、getpid()、gettimeofday()、shmget()、sysinfo()、uname()、ugetrlimit()、getuid()、time()",
            OperationMode.COMM_CONNECT: "recv()、socket()、recvfrom()、sendto()、send()、recvmsg()、sendmsg()",
            OperationMode.COMM_TRANSMIT: "connect()、pipe()、setsockopt()、bind()、getsockname()、getsockopt()",
        }
        for opMode, string in syscall_mode_table.items():
            lst = string.split('、')
            lst = [li.rstrip('()') for li in lst]
            syscall_mode_table[opMode] = lst
        # syscall -> mode
        self.syscall_convertor = {}
        for k,v_lst in syscall_mode_table.items():
            for v in v_lst:
                self.syscall_convertor[v] = k
        # print(self.mode_verb_convertor)
        # print('--')
        # print(self.syscall_convertor)
        pass

    def _print_mem_usage(self):
        # process = psutil.Process(os.getpid())
        mem_usage = psutil.Process(os.getpid()).memory_info().rss / 1024 ** 2
        print(f"=== mem_usage: {mem_usage:.2f} MB ===")  # in MiB 

    def _get_mem_usage(self) -> int:
        # process = psutil.Process(os.getpid())
        mem_usage = psutil.Process(os.getpid()).memory_info().rss / 1024 ** 2
        return mem_usage

    def resolve(self, syscall:str, en_verb:str, downcast=False) -> tuple[OperationMode, OperationMode]|bool:
        '''Determine if syscall matches en_verb (lemma). Return [OperationMode_syscall, OperationMode_verb] if match, otherwise False.'''
        mode_sys = self.syscall_convertor.get(syscall, None)
        if mode_sys is None:
            return False
        # acceptable_modes:list = [mode]
        # mode_expansion:dict = {} # mode 一對一對應，不做向下兼容 (CUD不包含read)
        # mem_before_create_lst = self._get_mem_usage()
        verb_list:list = self.mode_verb_convertor.get(mode_sys, None)
        # mem_after_create_lst = self._get_mem_usage()
        # print(f"\t=== diff of mem_usage calling self.mode_verb_convertor.get(): {mem_after_create_lst - mem_before_create_lst:.2f}  ===")
        # if mode == OperationMode.FILE_CUD:
        #     verb_list += self.mode_verb_convertor[OperationMode.FILE_CUD]
        if verb_list is None:
            del en_verb
            return False
        if en_verb in verb_list:
            del en_verb
            return mode_sys, mode_sys # the two modes are same
        del en_verb
        return False
    
    # 有 bug，勿用在verb上! 因為同個動詞會有可能出現在兩種mode中。 用在syscall上是可以的。
    def get_mode(self, action: str) -> OperationMode | None:
        '''get OperationMode for a `systemcall` action. Plz don't pass in en_verbs like 'send', judging ev_verb has bug. '''
        typeOfSyscall = self.syscall_convertor.get(action, None)
        if typeOfSyscall:
            return typeOfSyscall
        for typeOfVerb, verbList in self.mode_verb_convertor.items():
            if action in verbList:
                return typeOfVerb
        return None
        

if __name__ == '__main__':
    # test 1, <connects, 23.224.59.34:48080>
    sentence = 'the malware also connects to 23.224.59.34:48080 to send and receive remote shell commands'
    target_word = '23.224.59.34:48080'
    verb = find_verb_of_vocab(sentence, target_word)
    print(f'test1: {verb}')

    # test 2, <opened, /proc/cpuinfo>
    sentence = 'the virtual file /proc/cpuinfo is opened and read in words'
    target_word = '/proc/cpuinfo'
    verb = find_verb_of_vocab(sentence, target_word)
    print(f'test2: {verb}')

    # OperationEvaluator test case
    operationEvaluator = OperationEvaluator()
    res = operationEvaluator.resolve('linkat', 'read')
    print(res) # True [OperationMode.FILE_READ_CLOSE, OperationMode.FILE_READ_CLOSE]
    res = operationEvaluator.resolve('linkat', 'connect')
    print(res) # False
    res = operationEvaluator.resolve('ioctl', 'send')
    print(res) # [OperationMode.DEVICE, OperationMode.DEVICE]

    mode = operationEvaluator.get_mode('linkat')
    print("mode of 'linkat':", mode) # OperationMode.FILE_READ_CLOSE
    mode = operationEvaluator.get_mode('read')
    print("mode of 'read':", mode)   # OperationMode.FILE_READ_CLOSE
    mode = operationEvaluator.get_mode('connect')
    print("mode of 'connect':", mode) # OperationMode.COMM_TRANSMIT
    mode = operationEvaluator.get_mode('install')
    print("mode of 'install':", mode) # OperationMode.PROCESS_EXE
    mode = operationEvaluator.get_mode('send')
    print("mode of 'send':", mode) # OperationMode.COMM_CONNECT (其實也屬於DEVICE，但只能做到return一個mode)
    