import re

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
    def __init__(self, familyname:str=None) -> None:
        self.used_regex_set = set() # 紀錄被 find_spacial_token() 找到過的 regex
        self.regex_file = {
            "sed command": "bin/sed", 
            "startup": ["/etc/rc", "/etc/init.d/"],
            "process_info": "/proc/", 
            "sed temp file": "/etc/sed", 
            "selinx": "/selinux", 
            "sys": ["/sys/", "bin/", "lsb-release"], 
            "uname":"uname(.)($)",
            "dns": ["mtab", "nsswitch.conf", "resolv.conf", "/hosts"],
        }
        self.regex_process = {"command": ["^sh$", "^sed$"]} # must exact match
        self.regex_net = {
            "net address":[r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"], # 把 port 砍了 r":\d+" 會抓到時間，如 11:48
            "NIC": "eth[0-9]$"}
        self.regex_mem = {"Memory Address": "0x[0-9a-zA-Z]{8}"}
        self.regex_other = {"permission":"permission:{0,1}[0-9]{0,4}", "ID":["UID", "GID"]}
        self.all_regex_dict = {**self.regex_file,  **self.regex_process, **self.regex_net, **self.regex_mem, **self.regex_other}
        # 切換其他家族
        if familyname and familyname.lower() == 'xorddos':
            self.regex_file = {
                "sed command": "bin/sed", 
                "startup": ["/etc/rc", "/etc/init.d/"],
                "proc info":"/proc/", 
                "sed temp file":"/etc/sed", 
                "selinux":"/selinux",
                "boot":"/boot/", 
                "rootkit component":"/proc/rs_dev",
                "execution file created by xorddos":"/boot/[a-z]{10}", 
                "run":["/run/", "/var/run/"],
                "var": "/var/", 
                "perl": "/perl/", 
                "crontab": "/etc/cron",
                "init process": "bin/openrc", 
                "init service": "bin/insserv", 
                "uname": r"uname(\$|\.|$)"}
            self.regex_process = {
                "command": ["^sed$", "^sh$", "^chkconfig$", "^systemctl$", "update-rc.d"],
                "execution file created by xorddos": "/boot/[a-z]{10}", 
                "pipe": r"^pipe(\$|\.|$)",}
            self.regex_net = {
                "ip":r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 
                "port": [r"[a-zA-z]:\d{1,5}$", r"port \d{1,5}$"], # 空白需要額外寫 rule 辨識
                "ip + port": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$"}
            self.regex_mem = {"Memory Address": "0x[0-9a-zA-Z]{8}"}
            self.regex_ID = {"UID": r"UID(\$|\.|$)", "GID": r"GID(\$|\.|$)"}
            self.regex_permission = {"permission": "permission(\s)[0-9]{1,4}"}
            self.all_regex_dict = {**self.regex_file,  **self.regex_process, **self.regex_net, **self.regex_mem, **self.regex_ID, **self.regex_permission}
        # 整理 regex rules       
        self.all_regex_list = []
        for v in self.all_regex_dict.values():
            if isinstance(v,list):
                for i in v:
                    self.all_regex_list.append(i)
            else:
                self.all_regex_list.append(v)
        pass

    def get_all_regex(self) -> list: # should turn into classmethod
        return self.all_regex_list

    def get_used_regex(self) -> set:
        return self.used_regex_set

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
                if re.search(r, word, re.IGNORECASE):
                    # print("Match :", word, 'with regex', r)
                    result_list.append(RegexMatchResult(word, match_regex=r)) # 暫時忽略 type
                    self.used_regex_set.add(r)
        if len(result_list):
            return result_list     
        return None

    def get_regex_type(self): # should turn into classmethod
        pass

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
                    result_list.append(RegexMatchResult(word, match_regex=regex))
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