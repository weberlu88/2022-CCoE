import re

def find_spacial_token_regex(regex: str|list, sentence:str) -> str:
    ''' Return the matched 'word' if regex find it. If not found return None'''
    for word in sentence.split():
        if isinstance(regex, str):
            isMatch = re.match(regex, word)
            if isMatch:
                # print("Match :", word, 'with regex', regex)
                return word
        elif isinstance(regex, list):
            for r in regex:
                if re.match(r, word):
                    # print("Match :", word, 'with regex', r)
                    return word
        else:
            raise TypeError("regex must be str or list.")
    return None

class RegexMatchResult:
    def __init__(self, word: str, type: str=None, match_regex: str=None) -> None:
        self.word = word
        self.type = type
        self.match_regex = match_regex
        pass
    def __str__(self):
        return f"<RegexMatchResult word={self.word}, type={self.type}, match_regex={self.match_regex}>"
    def __repr__(self):
        return f"<RegexMatchResult word={self.word}, type={self.type}, match_regex={self.match_regex}>"

class RegexMaster:
    def __init__(self) -> None:
        self.used_regex_set = set() # 紀錄被 find_spacial_token() 找到過的 regex
        self.regex_file = {
            "sed command": ".*bin/sed", 
            "startup": ["/etc/rc.*", "/etc/init.d/.*"],
            "process_info": "/proc/.*", 
            "sed temp file": "/etc/sed.*", 
            "selinx": ".*/selinux.*", 
            "sys": ["/sys/.*", ".*bin/*", ".*lsb-release.*"], 
            "uname":"uname",
            "dns": [".*mtab.*", ".*nsswitch.conf.*", ".*resolv.conf.*", ".*/hosts.*"],
        }
        self.regex_process = {"command": ["^sh$", "^sed$"]} # must exact match
        self.regex_net = {
            "net address":["\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+", "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ":\d+"], # 說\d要背棄用了
            "NIC": "eth[0-9]*"}
        self.regex_mem = {"Memory Address": "0x[0-9a-zA-Z]{8}"}
        self.regex_other = {"permission":"Permission.*", "ID":["UID", "GID"]}
        # 整理 regex rules
        self.all_regex_dict = {**self.regex_file,  **self.regex_process, **self.regex_net, **self.regex_mem, **self.regex_other}
        self.all_regex_list = []
        for v in self.all_regex_dict.values():
            if isinstance(v,list):
                for i in v:
                    self.all_regex_list.append(i)
            else:
                self.all_regex_list.append(v)
        pass

    def get_all_regex(self) -> list:
        return self.all_regex_list

    def find_spacial_token(self, sentence:str) -> list[RegexMatchResult]:
        if not isinstance(sentence, str):
            try:
                sentence = str(sentence)
            except:
                raise TypeError("RegexMaster: Sentence cannot convert into string.")
        result_list = []
        for word in sentence.split():
            for r in self.all_regex_list:
                # print('r', r)
                if re.match(r, word):
                    # print("Match :", word, 'with regex', r)
                    result_list.append(RegexMatchResult(word, match_regex=r)) # 暫時忽略 type
                    self.used_regex_set.add(r)
        if len(result_list):
            return result_list     
        return None

# test case
if __name__ == '__main__':
    sentence = "How does the sed command edit a file? It creates a tmp file /etc/sedQhw17q to store your input first. Try 111 find 5.5.5.5:33"
    regex = "/etc/sed.*"
    regex_list = ["\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+", "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ":\d+"]
    result = find_spacial_token_regex(regex, sentence)
    print(result)

    '''
    [<RegexMatchResult word=sed, type=None, match_regex=^sed$>,
    <RegexMatchResult word=/etc/sedQhw17q, type=None, match_regex=/etc/sed.*>,
    <RegexMatchResult word=5.5.5.5:33., type=None, match_regex=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+>,
    <RegexMatchResult word=5.5.5.5:33., type=None, match_regex=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}>]
    '''