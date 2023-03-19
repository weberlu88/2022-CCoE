# import re
# import os
# from os import listdir
# from os.path import isfile, join
# from pathlib import Path
# import pandas as pd
from typing import Callable, Dict, List, get_type_hints
import pandas as pd
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
    def __init__(self) -> None:
        self.df = self.read_rule()
        self.update_syscall_list = list(self.df[self.df['ActionType'].isin(['UPDATE'])]['Syscall'].unique())
        pass

    def read_rule(self) -> pd.DataFrame:
        df = pd.read_csv('rule_dataset.csv')

        def clean_braces(x):
            x = x.replace("()", "").replace(",", "").replace(" ", "")
            return str(x)

        df['Syscall'] = df['Syscall'].apply(clean_braces)
        return df

    def translate_rule(self, entityType: str, enVerb: str, object: str=None) -> list[str] | None:
        ''' translate a given enverb into system call(s) with hardcoded rule '''
        entityType = entityType.upper()
        if entityType.startswith('PROC'):
            entityType = 'PROC'
        if entityType.startswith('NET'):
            entityType = 'NET'
        if entityType.startswith('INFO'):
            entityType = 'INFO'
        entityType_lst = ['FILE', 'PROC', 'DEVICE', 'INFO', 'NET']
        if entityType not in entityType_lst:
            return None
        
        # Get rules belongs to this entityType
        dataFileType = self.df[self.df['EntityType'] == entityType]
        dataEnVerb = dataFileType.loc[dataFileType['EnVerb'].isin([enVerb])]
        if len(dataEnVerb) == 0:
            return None
        return list(dataEnVerb['Syscall'].unique())

    def resolve(self, entityType: str, syscall:str, en_verb:str, downcast=False) -> bool:
        hit, isSysChange = False, False
        corresponding_syscall_list = self.translate_rule(entityType, en_verb)
        if corresponding_syscall_list and syscall in corresponding_syscall_list:
            hit = True
        if entityType.upper() == "FILE" and syscall in self.update_syscall_list:
            isSysChange = True
        return hit, isSysChange

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
    