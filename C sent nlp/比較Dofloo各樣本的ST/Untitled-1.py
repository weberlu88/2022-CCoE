# %%
import re
import os
from os import listdir
from os.path import isfile, join
from pathlib import Path
import pandas as pd
import pickle
from typing import Dict, List, get_type_hints
from styleframe import StyleFrame, Styler
from IPython.display import display

''' 自己寫的模組 '''
from cc_regex_script import RegexMatchResult, RegexMaster 
from cc_nlp_script import find_verb_of_vocab, OperationMode, OperationEvaluator
from cc_module_cust import AttackGraph, Node, Edge, FileTable #, build

# %% [markdown]
# ### Load 所有 Dofloo 的 object，計算並儲存其 regex

# %%
family = 'Xorddos' # Dofloo

sample_info = pd.read_csv('../../C malware info/sample_info.csv')
dofloo_info = sample_info[(sample_info['family'] == family) & 
            (~sample_info['filename'].isin(['8845355172c485813872f1bb1834de15.bin']))]
samplename_lst = dofloo_info['filename'].to_list()
samplename_lst = [name.split('.')[0] for name in samplename_lst]
print(f"family {family} has numOfSample {len(samplename_lst)}, first is {samplename_lst[0]}")

if family == 'Dofloo':
    samplename_lst = ['0046a78514a658b9b7a4e29e8581f85b'] # 只先使用這個 dof sample
if family == 'Xorddos':
    samplename_lst = ['0aefb67c01a24d05351b093455203fa2'] # 只先使用這個 xor sample

print('samplename:', samplename_lst)

# %%
class OperationPair:
    SYSCALL = 0
    VERB = 1

    def __init__(self, action:str, object:str, type:int=0, subject:str=None, step_number:int=None, original_object=None, original_sentence=None):
        self.object = object # regex
        self.action = action # verb or syscall
        self.type = type
        self.subject = subject
        self.step_number = step_number
        self.original_object = original_object # can store original matched word (object) from CTD
        self.original_sentence = original_sentence # can store the mathced sentence
        pass

    def __eq__(self, other): 
        if not isinstance(other, OperationPair):
            # don't attempt to compare against unrelated types
            return NotImplemented
        # Same if <action, object> pair is same (type is not consider yet)
        return self.action == other.action and self.object == other.object

    def __hash__(self) -> int:
        # necessary for instances to behave sanely in dicts and sets.
        return hash((self.action, self.object))

    def __str__(self) -> str:
        return f"<OP act={self.action}, obj={self.object}>"
    def __repr__(self) -> str:
        return str(self)
        
# test case
p_aa = OperationPair('a','a')
p_aaz = OperationPair('a','a')
p_ab = OperationPair('a','b')

print(p_aa == p_aaz) # True
print(set([p_aa, p_aaz])) # one element

def construct_sample_OPset(step_list: list, keep_src_node=False, debug=False) -> set:
    '''return a list of OPset. RegexMaster and family are gobal variable.'''
    if debug:
        print('step_list len:', len(set(step_list)))
    OPset_raw = set((src_node.name, dst_node.name, syscall) for (src_node, dst_node, syscall) in step_list) # object is raw
    if debug:
        print('OPset_raw len:', len(OPset_raw))
    regexMaster = RegexMaster(familyname=family)
    regex_pool = regexMaster.get_all_regex()
    OPset = set()
    for (src_node, dst_node, syscall) in OPset_raw:
        regex_dst_node_list = RegexMaster.find_spacial_token_with_regex(regex_pool, dst_node)
        if regex_dst_node_list is None or len(regex_dst_node_list) == 0:
            continue
        for regex_result in regex_dst_node_list:
            dst_node = regex_result.match_regex
            if keep_src_node:
                OPset.add(OperationPair(syscall, dst_node, subject=src_node)) # keep src_node in OP
            else:
                OPset.add(OperationPair(syscall, dst_node)) # only dst_node, syscall in OP
    if debug:
        print('OPset len:', len(OPset))
    return OPset

def construct_document_OPset(snetence_list:list, regex_list:list, keep_src_node=False, debug=False) -> set:
    pass

# test
# sample_OPset = construct_sample_OPset(asg.step_list, debug=True)

# %%
class Sample:
    def __init__(self, samplename:str, regex_set:set=None, special_token_dict=None, step_list=None) -> None:
        self.samplename: str = samplename
        self.regex_set: set = set()
        if regex_set:
            self.regex_set = regex_set
        self.special_token_dict = {}
        if special_token_dict:
            self.special_token_dict: dict = special_token_dict # list of dict
        self.OPset: set[OperationPair] = construct_sample_OPset(step_list)
        pass
    def __repr__(self) -> str:
        return f"<Sample self.samplename>"

''' 讀取 ASG 中的 set_of_object (就是這個樣本的 special_token_dict)，並歸納樣本的 regex_set '''
regexMaster = RegexMaster(familyname=family)
regex_pool = regexMaster.get_all_regex()
# total_used_regex = set()
samples: list[Sample] = []
for samplename in samplename_lst:
    with open(f'../../C ASG statistics 1115ver/saved_pkl/{family}/{samplename}.pkl', 'rb') as inp:
        asg: AttackGraph = pickle.load(inp) # asg.set_of_object is dict() (key:spacial token, value: type 首字大寫)
        sample = Sample(samplename, special_token_dict=asg.set_of_object, step_list=asg.step_list)
        sample.regex_set = set(regex_pool) # 直接使用志剛寫的作為這個樣本的 baseline
        # for obj in sample.special_token_dict.keys():
        #     matched_list: list[RegexMatchResult] = regexMaster.find_spacial_token(obj)
        #     if matched_list:
        #         # print(obj, matched_list)
        #         [sample.regex_set.add(m.match_regex) for m in matched_list]
        #         # [total_used_regex.add(m.match_regex) for m in matched_list]
        # print('------', sample.regex_set)
        # break
        samples.append(sample)
print(f'Exam: sample S1 matches {len(samples[0].regex_set)} of regex')
print(f'Size of regex_pool: {len(regex_pool)}, size of total_used_regex: {len(regexMaster.used_regex_set)}')

# %%
# 只差這四個不在 asg set_of_object 中 {'0x[0-9a-zA-Z]{8}', 'GID', 'UID', 'port \\d{1,5}$'}
set(regex_pool) - samples[0].regex_set

# %%
''' Save result to txt file 沒事不要 run ! '''
# total_regex = set()
# with open('./result/countof_regexset.txt', 'w', encoding='utf-8') as opf:
#     # header
#     opf.write('{:12s}'.format('Sample no.'))
#     for i in range(len(samples)):
#         if i+1 < 10:
#             opf.write(f' S{i+1} ')
#         else:
#             opf.write(f'S{i+1} ')
#     opf.write('\n')
#     # opf.write('{:12s}'.format('# of regex'))
#     num_of_regex_string = '{:12s}'.format('# of regex')
#     num_of_objects_string = '{:12s}'.format('# of object ') # 所有的類別喔! 無過濾
#     for i in range(len(samples)):
#         # opf.write(f'{len(samples[i].regex_set):>3} ')
#         num_of_regex_string += f'{len(samples[i].regex_set):>3} '
#         num_of_objects_string += f'{len(samples[i].special_token_dict):>3} '
#     opf.write(num_of_objects_string+'\n')
#     opf.write(num_of_regex_string)
#     opf.write('\n{:12s}'.format('Sample hash'))
#     for i in range(len(samples)):
#         opf.write(f'{samples[i].samplename[:3]:>3} ')
#     opf.write('\n\n')
#     opf.write(f'Size of regex_pool: {len(regex_pool)}, size of total_used_regex: {len(regexMaster.used_regex_set)}\n\n')

#     # content of each sample
#     for i,s in enumerate(samples):
#         content_1 = f"S{i+1} has {len(s.regex_set)} of regex\n"
#         content_2 = f"regex_set: {s.regex_set}\n"
#         content_3 = f"special_token_dict: {s.special_token_dict.keys()}\n"
#         opf.writelines([content_1, content_2, content_3])
#         opf.write('\n\n')

# %% [markdown]
# ### Load Reports

# %%
report_fir_path = '../../C parse report/sentence csvs/'
# family, samplename, outputfolder = 'Xorddos', '???', './result'
outputfolder = './result'

def get_all_filenames(dir: str='./') -> list:
    ''' traverse root directory, and list directories as dirs and files as files. Return filenames in rootdir. '''
    files = [f for f in listdir(dir) if isfile(join(dir, f))]
    files.sort()
    return files

xor_report_names = [f for f in get_all_filenames(report_fir_path) if f.startswith(family)] # 只選擇這個家族的報告
xor_report_dfs = [pd.read_csv(f"{report_fir_path}{f}") for f in xor_report_names]
xor_report_names

# %%
xor_report_dfs[0]

# %% [markdown]
# ### 單篇文章的 Class 和 整個 Family 的 Class
# `baseline: Dict[str, list]` 改為 `regexMaster: RegexMaster`

# %%
class ReportEvalModel:
    def __init__(self, regex_set: set, sentences: pd.DataFrame, reportname:str=''):
        self.regex_pool: set[str] = regex_set # 樣本or家族含有的 regex 集合
        self.sentences = sentences # a df
        self.reportname = reportname
        cols = list(regex_pool)
        self.match_tbl = pd.DataFrame([[0]*len(cols)]*len(sentences), columns=cols)
        self.match_word:dict[(int,str), str] = dict() # key(idx_sent,regex) value(word:str)
        self.match_regex = set()
        self.doc_OPset:set[OperationPair] = set() # Set of doc's OperationalPair
        # self.regexMaster = regexMaster # 其實應該用 class function 就不用傳入一個物件
        self.match()

    def match(self) -> None:
        '''find baseline in sentences of report. Fill matching result in self.match_tbl.'''
        sentence_list = self.sentences['Content']
        for idx_sent, sent in enumerate(sentence_list):
            # print(idx_sent, sent)
            # find regexs in a sentence
            matched_list: list[RegexMatchResult] = RegexMaster.find_spacial_token_with_regex(self.regex_pool, sent)
            if not matched_list:
                continue
            for m in matched_list:
                this_re = m.match_regex
                matched_word = m.word
                self.match_word[(idx_sent,this_re)] = m.word # 紀錄被 search 到的單字
                # self.match_tbl.loc[idx_sent,this_re] = 1 # mark as found 節省空間
                self.match_regex.add(this_re)
                en_verb = find_verb_of_vocab(sent, m.word)
                # print(f"---\nen_verb: {en_verb}, m.word: {m.word}, sent: {sent}") # 列印所有動詞抓取情形
                if en_verb:
                    self.doc_OPset.add(OperationPair(en_verb, this_re, type=OperationPair.VERB, original_object=m.word)) # has verb
                else:
                    self.doc_OPset.add(OperationPair(None, this_re, type=OperationPair.VERB, original_object=m.word)) # no verb
        pass
    
    def get_match_sentences(self) -> pd.DataFrame:
        result = self.match_tbl.copy()
        result['match'] = result.sum(axis=1)
        return result
    
    def get_match_regexs(self) -> set:
        return self.match_regex

    def get_match_word(self, idx_sent:int, regex:str) -> str:
        return self.match_word[(idx_sent, regex)]

class FamilySet:
    '''一個 malware family report 集合'''
    def __init__(self, familyname:str, regexMaster: RegexMaster, sample: Sample=None):
        self.familyname = familyname
        self.regexMaster = regexMaster
        self.num_of_used_regex = len(regexMaster.used_regex_set) # 這個家族含規則的總數量 (unoin by all samples)
        self.sample = None
        if sample:
            self.sample = sample
            self.num_of_used_regex = len(sample.regex_set) # 改以這個樣本規則的總數量為基準
        self.rem_lst: List[ReportEvalModel] = [] # list of ReportEvalModel under this family
        self.result_tbl = None

    def add_rem(self, sentences: pd.DataFrame, reportname: str=''):
        '''新增 report 到 FamilySet 中，需傳入文本和報告名稱，會沿用 FamilySet 的 baseline.'''
        if self.sample:
            rem = ReportEvalModel(list(self.sample.regex_set), sentences, reportname) # 基準是 Sample
            self.rem_lst.append(rem)
            return
        rem = ReportEvalModel(self.regexMaster, sentences, reportname) # 基準是 Family union # need fix -> no first arg now
        self.rem_lst.append(rem)

    def calc_report_coverage_score(self, match_regexs: list[str], apply_weight=False) -> float:
        '''計算這篇報告的 coverage_score，未處理分母為0之情形'''
        if not apply_weight:
            return len(match_regexs) / self.num_of_used_regex # 無權種的算法，分母是家族 wide
        ''' 以下 有權重的算法尚未修改，必出 bug '''
        # denominator = sum(self.regexMaster['weight']) # 分母
        # numerator = 0 # 分子
        # for b, w in zip(self.regexMaster['text'], self.regexMaster['weight']):
        #     if b in match_baselines:
        #         numerator += w
        # return numerator/denominator

    def show_result(self, apply_weight: bool=False, base_on_sample = True):
        '''print and return result table. baselinse(x) * report(y).'''
        column_names = ['report_name','ttl_match','coverage_score']
        if base_on_sample:
            column_names.extend(list(self.sample.regex_set))
        else:
            column_names.extend(list(regexMaster.used_regex_set))
        result_tbl = pd.DataFrame([[0]*len(column_names)]*len(self.rem_lst), columns=column_names)
        for i,rem in enumerate(self.rem_lst):
            match_regexes = rem.get_match_regexs() # 這篇報告含有哪些 baseine:set
            c_score = self.calc_report_coverage_score(match_regexes, apply_weight=apply_weight)
            result_tbl.loc[i,'report_name'] = rem.reportname
            result_tbl.loc[i,'ttl_match'] = len(match_regexes)
            result_tbl.loc[i,'coverage_score'] = f'{c_score:.4}'
            for b in match_regexes:
                result_tbl.loc[i,b] = 1
            print(rem.reportname, match_regexes)
        display(result_tbl)
        return result_tbl

# %% [markdown]
# ### Run Script: 存檔每篇報告的 matched sentence (以樣本的 regex set 為基準)
# 比較樣本間的辨別度，有 n 個樣本，就會跑 n 變，得出 n 個結果 (FanilySet)

# %%
def run_family_set_procedure(sample: Sample) -> FamilySet:
    # family, regexMaster is global variable
    fset = FamilySet(family, regexMaster, sample=sample)
    for i,rdf in enumerate(xor_report_dfs):
        # rem = ReportEvalModel(base_data, rdf, dofloo_report_names[i])
        fset.add_rem(rdf, xor_report_names[i])
    # result_tbl = fset.show_result(apply_weight=False)
    # result_tbl.to_csv(f'{outputfolder}/{family}_{sample.samplename[:3]}_FamilySet_by_Regex.csv', index=False)
    # print(f"Sample {sample.samplename[:3]} has ttl_match {result_tbl['ttl_match'].sum()} on all documents.") 

    # Calculate metrics
    for rem in fset.rem_lst:
        # asg_object = set([op.object for op in sample.OPset])
        # ctd_object = set([op.object for op in rem.doc_OPset])
        if rem.reportname != 'Xorddos-Microsoft.csv': # 除錯用
            continue
        print(f"\nSample {rem.reportname}")

        # R_malObj 比較物件
        asg_object = set([op.object for op in sample.OPset])
        ctd_object = set([op.object for op in rem.doc_OPset])
        ctd_object = ctd_object.intersection(asg_object)
        numerator = len(ctd_object) # 分子
        denominator = len(asg_object) # 分母
        R_malObj = 0 if numerator == 0 else numerator/denominator
        print(f"\t#R_malObj\n\tnum of ctd objects: {numerator}, num of asg objects: {denominator}. R_malObj is {R_malObj:.4f}")

        # R_malSysObj 比較系統物件
        asg_sysobj = list(filter(lambda object: object.find('/etc') != -1, asg_object))
        ctd_sysobj = list(filter(lambda object: object.find('/etc') != -1, ctd_object))
        numerator = len(ctd_sysobj)
        denominator = len(asg_sysobj)
        R_malSysObj = 0 if numerator == 0 else numerator/denominator
        print(f"\t#R_malSysObj\n\tnum of ctd objects: {numerator}, num of asg objects: {denominator}. R_malSysObj is {R_malSysObj:.4f}")

        # R_malOps 比較動作和物件
        asg_OPset = sample.OPset
        ctd_OPset = rem.doc_OPset
        operationEvaluator = OperationEvaluator()
        numerator, denominator, hits = 0, len(asg_OPset), []
        print(f"len(asg_OPset): {len(asg_OPset)}, len(ctd_OPset): {len(ctd_OPset)}")
        # 每一個 asg_op 跟所有同物件的的 ctd_op 進行 resolve() 比對，來判斷此 asg_op 是否被提及
        i = 0
        for asg_op in asg_OPset: 
            i += 1
            print(f"no.{i} asg_op {asg_op}")
            target_obj = asg_op.object
            ctdSameObjOps = [x for x in ctd_OPset if x.object == target_obj]
            for ctd_op in ctdSameObjOps:
                hit = operationEvaluator.resolve(asg_op.action, ctd_op.action)
                if hit:
                    numerator += 1
                    hits.append((asg_op, ctd_op))
                    break
        R_malOps = 0 if numerator == 0 else numerator/denominator
        print(f"\t#R_malOps\n\tnum of matched asg op: {numerator}, num of asg op: {denominator}. R_malOps is {R_malOps:.4f}")

        # R_malChangeOps 篩選出系統物件的動作
        sys_hits = [pair for pair in hits if pair[0].object.find('/etc') != -1]
        numerator = len(sys_hits)
        R_malChangeOps = 0 if numerator == 0 else numerator/denominator
        print(f"\t#R_malChangeOps\n\tnum of matched asg op: {numerator}, num of asg op: {denominator}. R_malChangeOps is {R_malChangeOps:.4f}")

        if hits:
            print("\n\thits")
            for asg_op, ctd_op in hits:
                print(f"\t{asg_op}, {ctd_op}")
        if sys_hits:
            print("\n\tsys_hits")
            for asg_op, ctd_op in sys_hits:
                print(f"\t{asg_op}, {ctd_op}")

        del asg_OPset, ctd_OPset, hits, sys_hits

    return fset

# %%
def save_match_sent_to_excel(fset: FamilySet, sample_name=None):
    columns = ['report','regex','matched word','sentence number','sentence']
    if sample_name:
        output_xlsx = f'{outputfolder}/{family}_{sample_name[:3]}_report_match_sent.csv'
    else:
        output_xlsx = f'{outputfolder}/{family}_union_report_match_sent.csv'
    has_match = sum([len(rem.get_match_regexs()) for rem in fset.rem_lst])
    if has_match == 0:
        print('no matches in CTI reports') # with open 一定要寫入，若全空則直接不開檔
        return
    # with pd.ExcelWriter(output_xlsx, engine='openpyxl') as writer:
    
    # 遍歷報告，一個 rem: ReportEvalModel 代表一篇報告
    csv_data = []
    match_sentence_ttlcnt = 0
    for rem in fset.rem_lst:
        reportname = rem.reportname.split('.')[0]
        if len(rem.get_match_regexs()) == 0: # 如果報告中無 regex 跳過不紀錄
            continue
        # sheet_data = [] # shape = columns_len * match_sent_len
        sent_df = rem.get_match_sentences()
        sent_content_lst = rem.sentences['Content'] # 報告中的每個句子
        match_sentence_ttlcnt += sent_df['match'].sum()

        # 遍歷每個含有 regex 的句子
        for sid, row in sent_df.iterrows():
            if row['match'] == 0:
                continue
            row.drop('match', inplace=True)
            row = row[row > 0]
            # print(row)
            # 考量每個句子可能含有多個 regex，故需寫成多行
            for i, v in row.items():
                insert_data = dict().fromkeys(columns)
                insert_data['report'] = reportname
                insert_data['regex'] = i
                insert_data['matched word'] = rem.get_match_word(sid, i)
                insert_data['sentence number'] = sid + 1
                insert_data['sentence'] = str(sent_content_lst[sid]).strip()
                # sheet_data.append(insert_data)
                csv_data.append(insert_data)
    df = pd.DataFrame(csv_data)
    # print(df)
    df.to_csv(output_xlsx, index=False)

            # 輸出 csv
            
            # 輸出 excel sheet
            # print(rem.reportname,'has', len(sheet_data),'matches')
            # output_sheet = pd.DataFrame(sheet_data)
            # # output_sheet.style.set_properties(subset=['sentence'])
            # styler = Styler(horizontal_alignment='left', vertical_alignment='top')
            # sf = StyleFrame(output_sheet, styler)
            # sf = sf.set_column_width(columns=['baseline'], width=20.0)
            # sf = sf.set_column_width(columns=['sentence number'], width=15.0)
            # sf = sf.set_column_width(columns=['sentence'], width=80.0)
            # sf.to_excel(writer, sheet_name=rem.reportname, index=False) #.save()
            # # output_sheet.to_excel(writer, sheet_name=rem.reportname, index=False)
    return match_sentence_ttlcnt

# 此行會執行並複寫 excel，執行完後要手動調整行距格式，小心使用


# %%
for sample in samples:
    fset = run_family_set_procedure(sample)
    # match_sentence_ttlcnt = save_match_sent_to_excel(fset, sample.samplename)
    # print(f'match_sentence_ttlcnt is {match_sentence_ttlcnt}\n---\n')
