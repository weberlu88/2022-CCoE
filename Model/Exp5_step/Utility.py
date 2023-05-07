import pandas as pd
import re
import ASG

#### 自動化 regex: 建立 dest_object_set ####

# 1. create set of objects (包含主詞 + 受詞 + type)
def create_set_of_objects(graph):
    '''return 2 lists seen_node_S, seen_node_O'''
    num_of_step = len(graph.step_list) # num_of_edges
    num_of_node_S = 0
    num_of_node_O = 0
    seen_node_S = []
    seen_node_O = []
    reverse_edge = ["read", "recv", "getsockopt"]

    for step in graph.step_list:
        node_S = step[0]
        node_O = step[1]
        edge_name = step[2]

        node_S_name = node_S.name + ":" + node_S.type
        if node_S_name not in seen_node_S:
            seen_node_S.append(node_S_name)
            num_of_node_S += 1

        node_O_name = node_O.name + ":" + node_O.type
        if node_O_name not in seen_node_O:
            seen_node_O.append(node_O_name)
            num_of_node_O += 1

        # if edge_name not in reverse_edge:

        #     node_S_name = node_S.name + ":" + node_S.type
        #     if node_S_name not in seen_node_S:
        #         seen_node_S.append(node_S_name)
        #         num_of_node_S += 1

        #     node_O_name = node_O.name + ":" + node_O.type
        #     if node_O_name not in seen_node_O:
        #         seen_node_O.append(node_O_name)
        #         num_of_node_O += 1
        # else:

        #     node_S_name = node_S.name + ":" + node_S.type
        #     if node_S_name not in seen_node_O:
        #         seen_node_O.append(node_S_name)
        #         num_of_node_O += 1

        #     node_O_name = node_O.name + ":" + node_O.type
        #     if node_O_name not in seen_node_S:
        #         seen_node_S.append(node_O_name)
        #         num_of_node_S += 1

#     print("num_of_step:", num_of_step)
#     print("num_of_node_S:", num_of_node_S)
#     print("num_of_node_O:", num_of_node_O)
    
    return seen_node_S, seen_node_O
# 2. 從 seen_node_O 中找出 dest_objects set
def get_dest_objects_set(seen_node_O):
    set_of_objects = []
    for node in seen_node_O:
        node_split = node.split(":")
        if len(node_split) > 2:
            node_name = node_split[0] + ":" + node_split[1]
        else:
            node_name = node_split[0]
        set_of_objects.append(node_name)
        set_of_objects = sorted(set_of_objects)
    
    return set_of_objects

# 3. 從 dest_objects set 中找出屬於 Process 類別的部分 = set_of_file_proc
def get_set_of_proc_O(set_of_objects, graph):
    set_of_proc_O = {}

    for step in graph.step_list:
        src_node = step[0]
        dest_node = step[1]
        edge_name = step[2]
        reverse_edge = ["read", "recv", "getsockopt"]

        src_type_eq_des_type = (src_node.type == dest_node.type)

        if edge_name not in reverse_edge:                   
            # dest
            if dest_node.type == "p":    
                if dest_node.name not in set_of_proc_O:
                    set_of_proc_O[dest_node.name] = 1
                else:
                    set_of_proc_O[dest_node.name] += 1 
        else:
            # dest
            if src_node.type == "p":      
                if src_node.name not in set_of_proc_O:
                    set_of_proc_O[src_node.name] = 1
                else:
                    set_of_proc_O[src_node.name] += 1
#     ### set ###
#     print("File:")
#     print(len(set_of_file_O), "set_of_file_O:", set_of_file_O)    
    return list(set_of_proc_O.keys())

# 3. 從 dest_objects set 中找出屬於 File 類別的部分 = set_of_file_O
def get_set_of_file_O(set_of_objects, graph):
    set_of_file_O = {}

    for step in graph.step_list:
        src_node = step[0]
        dest_node = step[1]
        edge_name = step[2]
        reverse_edge = ["read", "recv", "getsockopt"]

        src_type_eq_des_type = (src_node.type == dest_node.type)

        if edge_name not in reverse_edge:                   
            # dest
            if dest_node.type == "f" or dest_node.type == "c":    
                if dest_node.name not in set_of_file_O:
                    set_of_file_O[dest_node.name] = 1
                else:
                    set_of_file_O[dest_node.name] += 1 
        else:
            # dest
            if src_node.type == "f" or src_node.type == "c":      
                if src_node.name not in set_of_file_O:
                    set_of_file_O[src_node.name] = 1
                else:
                    set_of_file_O[src_node.name] += 1
#     ### set ###
#     print("File:")
#     print(len(set_of_file_O), "set_of_file_O:", set_of_file_O)    
    return set_of_file_O

# 4. 刪除一些不用撰寫 regex 的 file
def prun_set_of_file_O(set_of_file_O):


    set_of_objects_file = [] # without filter_file = [".", "/", "/prober", "Unknown", "malware"]

    filter_file = [".", "/", "./", "/prober", "Unknown", "malware"]
    for file_name in set_of_file_O:
        if file_name not in filter_file:
            set_of_objects_file.append(file_name)
            set_of_objects_file = sorted(set_of_objects_file)

#     print(set_of_objects_file)
    return set_of_objects_file

def get_set_of_objects_file(graph):
    seen_node_S, seen_node_O = create_set_of_objects(graph)
    set_of_objects = get_dest_objects_set(seen_node_O)
    set_of_file_O = get_set_of_file_O(set_of_objects, graph)
    set_of_objects_file = prun_set_of_file_O(set_of_file_O)
    
    return set_of_objects_file

#### 自動化 regex: 建立 rule base ####
def rule_to_regex(rule):
    # . --> \.
    # * --> .*
    
    rule = rule.replace(".", "\.")
    rule = rule.replace("*", ".*")
    
    return rule

def name_handler(dest_object: str) -> str:
    prefixs = ["/usr/local/share/*", "/usr/share/*", "/usr/include/*", "/var/cache/*", "/var/lib/*", "/var/mail/*",
                      "/var/opt/*", "/opt/*", "/opt/*/bin/*", "/opt/*/man/*"]  
    
    for prefix in prefixs:
        if re.search(prefix, dest_object):
            
            indicator = dest_object[len(prefix)-1:].split("/")[0]
            
#             return prefix[0:-1] + indicator
            return ".*/" + indicator + "/.*"

            
#             indicator = path[len(prefix):].split("/")[0]
#             return prefix + indicator
    
    return False
        
def bin_handler(dest_object: str) -> str:
    prefixs = ["/ffp/bin/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/"]
    
    for prefix in prefixs:
        pre_len = len(prefix)
        if prefix == dest_object[0:pre_len]:
            return "/.*bin/" + dest_object[pre_len:]
    
    
    return False

def build_RULES_DICT(path="Basic Search Rule.xlsx"):
    DIR_NAME = ['etc', 'proc', 'dev', 'usr', 'var', 'boot', 'opt', 'run', 'srv', 'home', 'media', 'mnt', 'sys']
    PATH = path
    RULES_DICT = {}

    for NAME in DIR_NAME:

        df = pd.read_excel(PATH, sheet_name=NAME)
        df_F_Rule = df["F_Rule"].dropna()
        df_D_Rule = df["D_Rule"].dropna()

        temp_F_Regex = []
        temp_D_Regex = []

        # 1 rule to regex
        for f_rule in df_F_Rule:
            temp_F_Regex.append(rule_to_regex(f_rule))

        for d_rule in df_D_Rule:
            temp_D_Regex.append(rule_to_regex(d_rule))

        # 2 建造 rule dict: key = dir_name, value = [F_Rules, D_Rules] (F_Rules、D_Rules 都是 list)
        RULES_DICT[NAME] = [temp_F_Regex, temp_D_Regex]

    return RULES_DICT

def special_case_handler(dest_object):
    special_case_list = ["/dict/words", ".*/selinux", ".*/perl/.*"]

    for rule in special_case_list:
        if re.search(rule, dest_object):
            return rule


def match_search_rule(dest_object: str, RULES_DICT: dict) -> str:
    
    # print(dest_object, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    
    # 處理 bin 相關的物件
    if bin_handler(dest_object):
        return bin_handler(dest_object)
        
    
    prefix = dest_object.split("/")[1]
    
    ## 有一個 object 直接是 /selinux，需要額外處理 
    if prefix in RULES_DICT:
        
        search_base_File = RULES_DICT[prefix][0]
        search_base_Directory = RULES_DICT[prefix][1]
    
        # 先嘗試用 file rule 進行 match
        for rule in search_base_File:
            if re.search(rule, dest_object):
                return rule


        # 再嘗試用 dir rule 進行 match
        match_rule = ""
        for rule in search_base_Directory:
            if re.search(rule, dest_object):
                if len(rule) > len(match_rule): # 找 match 最深的 rule
                    match_rule = rule



        # Q: name 先處理可能有問題 (Ex: /usr/share/ 直接 + name 回傳，就會忽略掉 /usr/share/doc/*
        # A: 應該先全部跑完，然後看跑出的規則屬於 /usr/share/* 就再用 handler 改成 /usr/share/ + name
        name_prefixs = ["/usr/local/share/.*", "/usr/share/.*", "/usr/include/.*", "/var/cache/.*", "/var/lib/.*",
                        "/var/mail/.*", "/var/opt/.*", "/opt/.*", "/opt/.*/bin/.*", "/opt/.*/man/.*"]    

        if match_rule in name_prefixs:
            return name_handler(dest_object)
        elif match_rule != "":
            return match_rule
        else:

            ### Special Case ###

            if dest_object == "uname":
                return "uname"
#             # 處理 selinx
#             elif "/selinux" in dest_object:
#                 return ".*/selinux"
            else:
                return False
            
    ## 有一個 object 直接是 /selinux，需要額外處理         
    else:
        return False
    

def build_file_regex(set_of_objects_file, RULES_DICT):
    regex_match_file = {}
    regex_non_match_file = []
    
    for file_name in set_of_objects_file:

        ### handling special case
        if special_case_handler(file_name):
            if special_case_handler(file_name) not in regex_match_file:
                regex_match_file[special_case_handler(file_name)] = [file_name]
            else:
                regex_match_file[special_case_handler(file_name)].append(file_name)
            continue

        # if len(file_name.split("/")) == 1:
        #     print("Err:", file_name)
        #     break


        prefix = file_name.split("/")[1]
        regex = match_search_rule(file_name, RULES_DICT)
        
        if regex != False:
            if regex not in regex_match_file:    
                regex_match_file[regex] = [file_name]
            else:
                regex_match_file[regex].append(file_name)
        else:
            # 如果 object 的 file name == prefix 例如: /boot  ； 但不能抓到 /selinux，所以要確認 prefix in RULES_DICT
            if file_name == "/" + prefix and prefix in RULES_DICT:
                regex = "/" + prefix
                regex_match_file[regex] = [file_name]
            else:
                regex_non_match_file.append(file_name)
    
    if ".*/perl5/.*" in regex_match_file:
        regex_match_file[".*/perl/.*"] += regex_match_file[".*/perl5/.*"]
        regex_match_file.pop(".*/perl5/.*", None)

    return regex_match_file, regex_non_match_file

def get_set_of_dict(graph):
    set_of_dict = {"File":[], "Process":[], "Net":[], "Memory":[], "Other":[]}
    for key in graph.set_of_object:
        set_of_dict[graph.set_of_object[key]].append(key)

    return set_of_dict

def get_proc_regex(graph):
    seen_node_S, seen_node_O = create_set_of_objects(graph)
    set_of_objects = get_dest_objects_set(seen_node_O)
    set_of_proc_O = get_set_of_proc_O(set_of_objects, graph)
    

    ignore_name = ['NO_PID', 'malware']
    
    proc_regex = []
    for proc in set_of_proc_O:
        if "/" not in proc: # 不用處理 malware 自行創建的執行檔，因為在File那邊已經處理了
            if (not proc.isnumeric()) and proc not in ignore_name:
                proc_regex.append("^" + proc + "$")
    
    return proc_regex

def get_regex_match_proc(graph):
    regexs = get_proc_regex(graph)
    regex_match_proc = {}

    seen_node_S, seen_node_O = create_set_of_objects(graph)
    set_of_objects = get_dest_objects_set(seen_node_O)
    set_of_proc_O = get_set_of_proc_O(set_of_objects, graph)
    ignore_name = ['NO_PID', 'malware']

    for proc in set_of_proc_O:
        if "/" not in proc and proc not in ignore_name: 

            for regex in regexs:
                if re.search(regex, proc): # match 成功

                    if regex not in regex_match_proc:
                        regex_match_proc[regex] = [proc]
                    else:
                        regex_match_proc[regex].append(proc)
    
    return regex_match_proc

def get_net_regex(graph):
    set_of_net_O = get_set_of_dict(graph)["Net"]

    net_regex = []
    
    ip_regex = ["\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "port \d+", "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+"]
    nic_regex = ["^eth.*"]

    for net_O in set_of_net_O:
        if re.search(ip_regex[0], net_O):
            if ("port \d+" not in net_regex):
                net_regex += ip_regex
                continue
        if re.search(nic_regex[0], net_O):
            if ("^eth.*" not in net_regex):
                net_regex += nic_regex 
                continue 
        if net_O == "NIC": # 避免畫圖時 sink 成 NIC 而抓不到 regex
            if ("^eth.*" not in net_regex):
                net_regex += nic_regex
                continue

    return net_regex

def get_regex_match_net(graph):
    regexs = get_net_regex(graph)
    regex_match_net = {}

    set_of_net_O = get_set_of_dict(graph)["Net"]
    # print("set_of_net_O:", set_of_net_O)

    for net_O in set_of_net_O:
        if net_O == "NIC":
            if "^eth.*" not in regex_match_net:
                regex_match_net["^eth.*"] = [net_O]

        for regex in regexs:
            if re.search(regex, net_O):
                if regex not in regex_match_net:
                    regex_match_net[regex] = [net_O]
                else:
                    regex_match_net[regex].append(net_O)

    return regex_match_net                


def get_mem_regex(graph):
    set_of_mem_O = get_set_of_dict(graph)["Memory"]
    if len(set_of_mem_O) > 0:
        mem_regex = ["0x[0-9a-zA-Z]{8}"]
    else:
        mem_regex = []

    return mem_regex

def get_regex_match_mem(graph):
    regexs = get_mem_regex(graph)
    regex_match_mem = {}

    set_of_mem_O = get_set_of_dict(graph)["Memory"]
    if len(set_of_mem_O) > 0:
        regex_match_mem["0x[0-9a-zA-Z]{8}"] = ["Memory Address"]

    return regex_match_mem

def get_ID_regex(graph):
    set_of_other_O = get_set_of_dict(graph)["Other"]

    ID_regex = []
    ignore_str = "Shared Memory ID"

    for other_O in set_of_other_O:
        if ignore_str not in other_O:
            if "ID" in other_O and other_O[0]:
                if "^" + other_O[0:3] + ".*" not in ID_regex:
                    ID_regex.append("^" + other_O[0:3] + ".*")

    return ID_regex

def get_regex_match_ID(graph):
    regexs = get_ID_regex(graph)
    regex_match_ID = {}

    set_of_other_O = get_set_of_dict(graph)["Other"]
    ignore_str = "Shared Memory ID"

    for other_O in set_of_other_O:
        if ignore_str not in other_O:
            if "ID" in other_O:
                for regex in regexs:
                    if re.search(regex, other_O):
                        if regex not in regex_match_ID:
                            regex_match_ID[regex] = [other_O]
                        else:
                            regex_match_ID[regex].append(other_O)

    return regex_match_ID

def get_premission_regex(graph):
    set_of_other_O = get_set_of_dict(graph)["Other"]

    prm_regex = []

    for other_O in set_of_other_O:
        if "Permission" in other_O:
            prm_regex = ["Permission", "Permission:[0-9]{3}"]
            break
    
    return prm_regex

def get_regex_match_permission(graph):
    regexs = get_premission_regex(graph)
    regex_match_premission = {}

    set_of_other_O = get_set_of_dict(graph)["Other"]

    for other_O in set_of_other_O:
        if "Permission" in other_O:
            for regex in regexs:
                if re.search(regex, other_O):
                    if regex not in regex_match_premission:
                        regex_match_premission[regex] = [other_O]
                    else:
                        regex_match_premission[regex].append(other_O)

    return regex_match_premission

def get_reduction_statistic(graph): # the graph is a non-reduciton graph, because we need to calculate the difference bewteen non-reduciton and reduction graph
    # count the reduciton # 要用尚未 reduce 的去計算
    seen_mem = [] # type = m_addr
    seen_NIC = [] # type = n
    # seen_ID = [] # type = other
    seen_time = [] # type = other
    # seen_sleep_duration = []  # type = other


    for i in range(len(graph.step_list)):
        src_node = graph.step_list[i][0]
        dest_node = graph.step_list[i][1]
        edge_name = graph.step_list[i][2]
        
        
        ### mem ###
        
        if src_node.type == "m_addr":
            if src_node.name not in seen_mem:
                seen_mem.append(src_node.name)
                
        
        if dest_node.type == "m_addr":
            
            if dest_node.name not in seen_mem:
                seen_mem.append(dest_node.name)
            
        ### time ### 
        time_edge = ["time", "gettimeofday"]
        if edge_name in time_edge:
            if dest_node.name not in seen_time:
                seen_time.append(dest_node.name)  
                
        ### NIC ###
        if dest_node.type == "n" and "eth" in dest_node.name:
            if dest_node.name not in seen_NIC:
                seen_NIC.append(dest_node.name)
                
    #     ### ID ###
    #     if edge_name[-2:] == "id":
    #         result = re.match("\d+",  dest_node.name)
    #         if result:
    # #             print(edge_name,  dest_node.name)
    #             if dest_node.name not in seen_ID:
    #                 seen_ID.append(dest_node.name)
                
    #     ### sleep ###
    #     if edge_name == "nanosleep" or edge_name == "sleep":
    #         if dest_node.name not in seen_sleep_duration:
    #             seen_sleep_duration.append(dest_node.name)
                

    num_of_mem_sink = len(seen_mem) - 1
    print("mem:",len(seen_mem), "->", 1, "sink:",  num_of_mem_sink)

    num_of_time_sink = len(seen_time) - 1
    print("time:",len(seen_time), "->", 1, "sink:",  num_of_time_sink)

    num_of_NIC_sink = len(seen_NIC) - 1
    print("NIC:",len(seen_NIC), "->", 1, "sink:",  num_of_NIC_sink)

    # num_of_ID_sink = len(seen_ID) - 1
    # print("ID:",len(seen_ID), "->", 1, "sink:",  num_of_ID_sink)

    # num_of_sleep_sink = len(seen_sleep_duration) - 1
    # print("Sleep:",len(seen_sleep_duration), "->", 1, "sink:",  num_of_sleep_sink)


def get_uni_step(graph):
    step_set = list(set(graph.step_list))
    step_set_id = {}
    for i in range(len(step_set)):
        step_set_id[step_set[i]] = str(i+1)   
        
    unique_step = {}

    for step in graph.step_list:
        src_node = step[0]
        dest_node = step[1]
        edge_name = step[2]

        temp_key = "Step_ID:" + step_set_id[step] + " " + src_node.name + " -> " + edge_name + " -> " + dest_node.name


        if temp_key not in unique_step:
            unique_step[temp_key] = 1
        else:
            unique_step[temp_key] += 1
            
    return unique_step

def get_step_reduction_statistic(unique_step):
    step_reduction = {}
    for key in unique_step:

        if unique_step[key] > 1:

            step_component = key.split(" ")[1:]
            step = ""
            for component in step_component:
                step += " " + component
        #     print(step)
        #     break
            reduction_num = unique_step[key] - 1
            if step not in step_reduction:
                step_reduction[step] = reduction_num
            else:
                step_reduction[step] += reduction_num
                
    return step_reduction

cache_unique_steplist = []
cache_nodecount:int = 0
cache_stepcount:int = 0

def get_sorted_uni_step(graph):
    '''list of [src_node, dest_node, edge_name]'''
    # return cache result if for same asg
    global cache_unique_steplist, cache_nodecount, cache_stepcount
    if len(graph.set_of_object) == cache_nodecount and len(graph.step_list) == cache_stepcount:
        return cache_unique_steplist
    
    index = 1
    set_of_step_list = list(set(graph.step_list))
    set_of_step_list.sort(key = graph.step_list.index)
    sorted_uni_step = []
    for step in set_of_step_list:
        src_node = step[0].name
        dest_node = step[1].name
        edge_name = step[2]
        
        sorted_uni_step.append([src_node, dest_node, edge_name])
        # print("step", index, ":", src_node, "->", edge_name, "->", dest_node)
        index += 1

    # store chche result
    cache_unique_steplist = sorted_uni_step
    cache_nodecount, cache_stepcount = len(graph.set_of_object), len(graph.step_list)

    return sorted_uni_step

class Step:
    '''Store an asg step's data'''
    def __init__(self, number, subject, syscall, object) -> None:
        self.num = number
        self.sub = subject
        self.obj = object
        self.call = syscall
        pass
    def callb(self) -> str:
        '''system call with braces'''
        return f"{self.call}()"
    def __eq__(self, other: object) -> bool:
        '''note: self.num will not be compare (這個方法目前用不到)'''
        if isinstance(other, Step):
            return self.sub == other.sub and self.obj == other.obj and self.call == other.call
        return False
    def __hash__(self):
        return hash((self.sub, self.obj, self.call))

def query_origin_steplist(graph:ASG.AttackGraph, syscall:str, regex:str) -> list[str]:
    '''Query the origin asg steps (triplet), return in a list of formatted string.\n
    Input:
        @graph: ASG.AttackGraph
        @syscall: system call
        @regex: the regex of object
    Ouput example:
        - query `get_origin_steplist(graph, 'rename', '/etc/rc\.local')` will get:
        - [`'  65. /etc/sedQUGLbs -> rename()   -> /etc/rc.local'`, `' 141. /etc/sedQhw17q -> rename()   -> /etc/rc.local'`]
    '''
    # take the first appearence step (unique) and set the step number
    steplist = get_sorted_uni_step(graph)
    steplist = [Step(i+1, step[0], step[2], step[1]) for i,step in enumerate(steplist)]
    # print('total len of steplist:', len(steplist)) #  284 for dofloo

    # filter object and syscall with input regex
    steplist = [step for step in steplist if re.search(regex, step.obj, re.IGNORECASE)] 
    steplist = [step for step in steplist if step.call == syscall]
    # turn object in to string
    steplist = [f"{step.num:4}. {step.sub:<7} -> {step.callb():10} -> {step.obj}" for step in steplist]
    return steplist

# example call
# query_origin_steplist(graph, 'rename', '/etc/rc\.local') # step 64, 140, 183
# query_origin_steplist(graph, 'connect', '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}') # step 270