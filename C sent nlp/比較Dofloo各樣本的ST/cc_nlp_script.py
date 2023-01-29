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
    FILE_READ = 1
    FILE_CUD = 2
    # FILE_DELETE = 3 # delete can done with unlink() rename() open()
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
        # mode has en_verb
        self.mode_verb_convertor = {
            OperationMode.FILE_READ: "read、gather、check、find、check、close、fetch、look",
            OperationMode.FILE_CUD: "add、format、modify、write、overwrite、create、set、change、delete、rename、open、drop、use、extract",
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
            OperationMode.FILE_READ: "linkat()、statfs()、stat()、lseek()、readlink()、munmap()、stat64()、access()、link()、lstat()、ppoll()、getcwd()、read()、fstat64()、dup2()、fstat()、fcntl64()、symlinkat()、umask()、newfstatat()、symlink()、getdents()、fcntl()、_newselect()、chdir()、close()",
            OperationMode.FILE_CUD: "rmdir()、mmap()、rename()、fchmod()、mmap2()、mkdir()、fchown()、write()、open()、openat()、unlink()、unlinkat()、remove()",
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

    def resolve(self, syscall:str, en_verb:str) -> bool:
        '''Determine if syscall matches en_verb (lemma). Return True if match, otherwise False.'''
        mode = self.syscall_convertor.get(syscall, None)
        if mode is None:
            return False
        # acceptable_modes:list = [mode]
        # mode_expansion:dict = {} # mode 一對一對應，不做向下兼容 (CUD不包含read)
        # mem_before_create_lst = self._get_mem_usage()
        verb_list:list = self.mode_verb_convertor.get(mode, None)
        # mem_after_create_lst = self._get_mem_usage()
        # print(f"\t=== diff of mem_usage calling self.mode_verb_convertor.get(): {mem_after_create_lst - mem_before_create_lst:.2f}  ===")
        if mode == OperationMode.FILE_CUD:
            verb_list += self.mode_verb_convertor[OperationMode.FILE_CUD]
        if verb_list is None:
            return False
        if en_verb in verb_list:
            return True
        return False

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
    print(res) # True
    res = operationEvaluator.resolve('linkat', 'connect')
    print(res) # False