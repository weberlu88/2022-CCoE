import re
import ASG
import Utility

class RegexMatchResult:
    def __init__(self, word: str, type: str=None, match_regex: str=None) -> None:
        self.line = ''
        self.word = word
        self.type = type
        self.match_regex = match_regex
        pass
    def __str__(self):
        return f"<RegexMatchResult word={self.word}, type={self.type}, match_regex={self.match_regex}>"
    def __repr__(self):
        return f"<RegexMatchResult word={self.word}, type={self.type}, match_regex={self.match_regex}>"

class RegexMaster:
    def __init__(self, graph:ASG.AttackGraph,familyname:str=None) -> None:
        self.used_regex_set = set() # 紀錄被 find_spacial_token() 找到過的 regex
        set_of_objects_file = Utility.get_set_of_objects_file(graph)

        # rule dict from .xlsx
        RULES_DICT = Utility.build_RULES_DICT() 

        # use the rule dict to build up the regex, it may not match all objects
        regex_match_file, regex_non_match_file = Utility.build_file_regex(set_of_objects_file, RULES_DICT) 
        self.file_regex:list[str] = list(regex_match_file.keys()) # type 'FILE'
        self.proc_regex:list[str] = Utility.get_proc_regex(graph) # type 'PROC'
        self.net_regex:list[str]  = Utility.get_net_regex(graph)  # type 'NET'
        self.mem_regex:list[str]  = Utility.get_mem_regex(graph)  # type 'MEM' but dont have syscall rules
        self.ID_regex:list[str]   = Utility.get_ID_regex(graph)   # type 'ID'
        permission_regex:list[str] = Utility.get_premission_regex(graph)
        self.info_regex:list[str] = []
        infos = ['uname(.|$)','sysinfo']
        for info in infos:
            exit = False
            for x in self.file_regex:
                if re.search(info, x, re.IGNORECASE):
                    exit = True
                    break
            if exit:
                self.info_regex.append(info)
            self.file_regex = [ x for x in self.file_regex if re.search(info, x, re.IGNORECASE) is None ] # 從file裡抓出info的re
        self.file_regex.extend(permission_regex) # 把umask的檔案權限歸類為file
        
        # 合併 regex rules，其實是 used regex，無法取得所有的 regex
        self.all_regex_list = []
        self.all_regex_list.extend(self.file_regex) # 'FILE'
        self.all_regex_list.extend(self.proc_regex) # 'PROC'
        self.all_regex_list.extend(self.net_regex)  # 'NET'
        self.all_regex_list.extend(self.mem_regex)  # 'MEM'
        self.all_regex_list.extend(self.ID_regex)   # 'ID'
        self.all_regex_list.extend(self.info_regex) # 'INFO'

        self.all_type_list = ['FILE']*len(self.file_regex) + ['PROC']*len(self.proc_regex) \
                           + ['NET'] *len(self.net_regex)  + ['MEM']*len(self.mem_regex) \
                           + ['ID'] *len(self.ID_regex)    + ['INFO']*len(self.info_regex)
        assert len(self.all_regex_list) == len(self.all_type_list)
        # ['FILE', 'PROC', 'DEVICE', 'INFO', 'NET', 'ID'], 
        # DEVICE is not used cause it's resource bytes,
        # MEM is labeled but no syscall rules for him

        # store {regex -> mapped asg object list} relation
        self.regex_match_objects = {}
        self.regex_match_objects.update(regex_match_file)
        self.regex_match_objects.update(Utility.get_regex_match_proc(graph))
        self.regex_match_objects.update(Utility.get_regex_match_net(graph))
        self.regex_match_objects.update(Utility.get_regex_match_mem(graph))
        self.regex_match_objects.update(Utility.get_regex_match_ID(graph))
        self.regex_match_objects.update(Utility.get_regex_match_permission(graph))
        pass

    def get_obj_by_reg(self, reg:str) -> list[str]:
        try:
            return self.regex_match_objects[reg]
        except:
            return None

    def get_used_regex(self) -> set:
        return set(self.all_regex_list)

    def find_spacial_token(self, sentence:str) -> list[RegexMatchResult]:
        if not isinstance(sentence, str):
            try:
                sentence = str(sentence)
            except:
                raise TypeError("RegexMaster: Sentence cannot convert into string.")
        result_list = []
        for word in sentence.split():
            for i,r in enumerate(self.all_regex_list):
                # print('r', r)
                if re.search(r, word, re.IGNORECASE):
                    # print("Match :", word, 'with regex', r)
                    result_list.append(RegexMatchResult(word, match_regex=r, type=self.all_type_list[i])) # has type
                    self.used_regex_set.add(r)
        if len(result_list):
            return result_list     
        return None

    def get_regex_type(self, regex:str) -> str: # should turn into classmethod (but cannot since it require fields)
        ''' return the type(string) of regex. `['FILE', 'PROC', 'INFO', 'NET', 'ID', 'MEM']` '''
        try:
            i = self.all_regex_list.index(regex)
            return self.all_type_list[i]
        except ValueError:
            return None

    @classmethod
    def find_spacial_token_with_regex(cls, regex: str|list, sentence:str) -> list[RegexMatchResult]:
        ''' Return a list of RegexMatchResult which contains matched 'word' if regex find it. If not found return None'''
        if not isinstance(sentence, str):
            try:
                sentence = str(sentence)
            except:
                raise TypeError("RegexMaster: Sentence cannot convert into string.")
        result_list = []
        for word in sentence.split():
            if isinstance(regex, str):
                isMatch = re.search(regex, word, re.IGNORECASE)
                if isMatch:
                    # print("Match :", word, 'with regex', regex)
                    # i = cls.all_type_list.index()
                    result_list.append(RegexMatchResult(word, match_regex=regex)) # 暫時忽略 type
            elif isinstance(regex, list):
                for r in regex:
                    if re.search(r, word, re.IGNORECASE):
                        # print("Match :", word, 'with regex', r)
                        result_list.append(RegexMatchResult(word, match_regex=r)) # 暫時忽略 type
            else:
                raise TypeError("regex must be str or list.")
        if len(result_list):
            return result_list     
        return None

# test case
if __name__ == '__main__':
    sentence = "How does the sed command edit a file? It creates a tmp file /etc/sedQhw17q to store your input first. Try binary 111 find 5.5.5.5:33"
    regex = "/etc/sed.*"
    regex_list = [r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", r":\d+"]
    result = RegexMaster.find_spacial_token_with_regex(regex, sentence)
    print(result)

    '''
    [<RegexMatchResult word=sed, type=None, match_regex=^sed$>,
    <RegexMatchResult word=/etc/sedQhw17q, type=None, match_regex=/etc/sed.*>,
    <RegexMatchResult word=5.5.5.5:33., type=None, match_regex=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+>,
    <RegexMatchResult word=5.5.5.5:33., type=None, match_regex=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}>]
    '''