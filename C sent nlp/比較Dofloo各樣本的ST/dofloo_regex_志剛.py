import re

### set of objects ###
File = ['/usr/local/sbin/sed', '/usr/local/bin/sed', '/usr/sbin/sed', '/usr/bin/sed', '/sbin/sed', '/bin/sed',
'/etc/rc.local', '/etc/rc.d/rc.local', '/etc/init.d/boot.local', 
'/proc/self/exe', '/proc/net/dev', '/proc/stat',
'/etc/sedQUGLbs', '/etc/sedQhw17q', '/etc/sedvTqQwq', 
'/sys/fs/selinux', '/selinux', '/etc/selinux/config', 
'/sys/devices/system/cpu/online', 
'uname', '/prober', '.', '/dev/urandom' ]

Process = ['sh', 'sed', 'NO_PID', '1526', '1527', '1528', '1529']
Net = ['NIC', '23.236.66.13:50050', 'NO_SOCKET'] # (NIC = eth0、eth1、eth2……)
Memory = ['Memory Address']
Others = ['GID:0', 'UID:0', 'PID:1513', 'PID:1514', 'PID:1515', 'PID:1516', 'PID:1518', 'PID:1519', 'PID:1520', 'PID:1521', 'PID:1522', 'PID:1524',
'Permission:022', 'Permission:0700', 
'Sleep Duration', 'Timestamp', 
'status:0', 'status:1', 'status:2', 
'8192*1024 bytes', ]

all_objects = File + Process + Net + Memory + Others

### regex rule ###

regex_file = {
	"sed command": ".*bin/sed", 
	"startup": ["/etc/rc.*", "/etc/init.d/.*"],
	"process_info": "/proc/.*", 
	"sed temp file": "/etc/sed.*", 
	"selinx": ".*/selinux.*", 
	"sys": ["/sys/.*", "*bin/*", "*lsb-release"], 
	"uname":"uname",
	"dns": ["*mtab", "*nsswitch.conf", "*resolv.conf", "*/hosts"]
}

regex_process = {"command": ["sh", "sed"]}

regex_net = {"net address":["\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+", "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ":\d+"]
, "NIC": "eth[0-9]*"}

regex_mem = {"Memory Address": "0x[0-9a-zA-Z]{8}"}

regex_other = {"permission":"Permission.*", "ID":["UID", "GID"]}

all_regex_dict = {**regex_file,  **regex_process, **regex_net, **regex_mem, **regex_other}
all_regex_list = []

for v in all_regex_dict.values():
	if isinstance(v,list):
		for i in v:
			all_regex_list.append(i)
	else:
		all_regex_list.append(v)

### test 針對一個類別 ###
# for f in File:
# 	for key in regex_file:
# 		rule = regex_file[key]
# 		if isinstance(rule, list):
# 			for r in rule:
# 				isMatch = re.match(r, f)
# 				if isMatch:
# 					print("Match", key, ":", f)
# 					break
# 		else:
# 			isMatch = re.match(rule, f)
# 			if isMatch:
# 				print("Match", key, ":", f)

### test 針對所有 ###
for obj in all_objects:
	for regex in all_regex_list:
		isMatch = re.match(regex, obj)
		if isMatch:
			print("Match :", obj)
			break
