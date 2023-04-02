import pandas as pd
import re

#### 自動化 regex: 建立 dest_object_set ####

# 1. create set of objects (包含主詞、動詞)
def create_set_of_objects(graph):
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

        if edge_name not in reverse_edge:

            node_S_name = node_S.name + ":" + node_S.type
            if node_S_name not in seen_node_S:
                seen_node_S.append(node_S_name)
                num_of_node_S += 1

            node_O_name = node_O.name + ":" + node_O.type
            if node_O_name not in seen_node_O:
                seen_node_O.append(node_O_name)
                num_of_node_O += 1
        else:

            node_S_name = node_S.name + ":" + node_S.type
            if node_S_name not in seen_node_O:
                seen_node_O.append(node_S_name)
                num_of_node_O += 1

            node_O_name = node_O.name + ":" + node_O.type
            if node_O_name not in seen_node_S:
                seen_node_S.append(node_O_name)
                num_of_node_S += 1

#     print("num_of_step:", num_of_step)
#     print("num_of_node_S:", num_of_node_S)
#     print("num_of_node_O:", num_of_node_O)
    
    return seen_node_O
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

    filter_file = [".", "/", "/prober", "Unknown", "malware"]
    for file_name in set_of_file_O:
        if file_name not in filter_file:
            set_of_objects_file.append(file_name)
            set_of_objects_file = sorted(set_of_objects_file)

#     print(set_of_objects_file)
    return set_of_objects_file

def get_set_of_objects_file(graph):
    seen_node_O = create_set_of_objects(graph)
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
            return ".*/" + indicator + ".*/"

            
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
    special_case_list = ["uname", "/dict/words", ".*/selinux"]

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
            regex_match_file[special_case_handler(file_name)] = [file_name]
            continue

        # if file_name == "uname":
        #     regex_match_file["uname"] = [file_name]
        #     continue
        
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
    
    return regex_match_file, regex_non_match_file

def get_set_of_dict(graph):
    ''' return 5 types of all object including "subject" and "object".
     `{"File":[], "Process":[], "Net":[], "Memory":[], "Other":[]}` '''
    set_of_dict = {"File":[], "Process":[], "Net":[], "Memory":[], "Other":[]}
    for key in graph.set_of_object:
        set_of_dict[graph.set_of_object[key]].append(key)

    return set_of_dict

def get_proc_regex(graph):
    seen_node_O = create_set_of_objects(graph)
    set_of_objects = get_dest_objects_set(seen_node_O)
    set_of_proc_O = get_set_of_proc_O(set_of_objects, graph)
    

    ignore_name = ['NO_PID']
    
    proc_regex = []
    for proc in set_of_proc_O:
        if (not proc.isnumeric()) and proc not in ignore_name:
            proc_regex.append(proc)
    
    return proc_regex

def get_net_regex(graph):
    set_of_net_O = get_set_of_dict(graph)["Net"]

    net_regex = []
    
    ip_regex = ["\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "port d+ ", "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:d+"]
    nic_regex = ["eth.*"]

    for net_O in set_of_net_O:
        if re.search(ip_regex[0], net_O):
            if ("port d+ " not in net_regex):
                net_regex += ip_regex
                continue
        if re.search(nic_regex[0], net_O):
            if ("eth.*" not in net_regex):
                net_regex += nic_regex 
                continue 

    return net_regex

def get_mem_regex(graph):
    set_of_mem_O = get_set_of_dict(graph)["Memory"]
    if len(set_of_mem_O) > 0:
        mem_regex = ["0x[0-9a-zA-Z]{8}"]
    else:
        mem_regex = []

    return mem_regex

def get_ID_regex(graph):
    set_of_other_O = get_set_of_dict(graph)["Other"]

    ID_regex = []

    for other_O in set_of_other_O:
        if "ID" in other_O and other_O[0]:
            if other_O[0:3] + ".*" not in ID_regex:
                ID_regex.append(other_O[0:3] + ".*")

    return ID_regex

def get_premission_regex(graph):
    set_of_other_O = get_set_of_dict(graph)["Other"]

    prm_regex = []

    for other_O in set_of_other_O:
        if "Permission" in other_O:
            prm_regex = ["Permission", "Permission:[0-9]{3}"]
            break
    
    return prm_regex

