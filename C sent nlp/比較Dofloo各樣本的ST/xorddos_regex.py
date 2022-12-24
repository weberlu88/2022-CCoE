import re

file = ['/bin/sed', '/boot', '/boot/auqrvglpdz', '/boot/awroivjpkx', '/boot/bkrlffbdxs', '/boot/bsthdzgvmt', '/boot/bsuztxmack', '/boot/bthcxsfqan', '/boot/btiipgrbod', '/boot/bxzcujmwuj', '/boot/culylmxbnn', '/boot/cuzvqbtvfd', '/boot/dczbbqscrr', '/boot/devawlqrit', '/boot/dgbfmcdgie', '/boot/eirlnrbbue', '/boot/fgqxqatvys', '/boot/frdsmulhvu', '/boot/ftrnncnlir', '/boot/fykepenmvn', '/boot/fzmicupinj', '/boot/gvqambdbei', '/boot/gzouwclwnr', '/boot/hbzgcgpgrl', '/boot/hlgpkoezsl', '/boot/hucenabudx', '/boot/iphpevdezt', '/boot/iswqwsprgu', '/boot/ixfnusqrgg', '/boot/jpyqhyfzey', '/boot/kfiegjyafw', '/boot/kfsglskbdb', '/boot/kkxlhyzfmp', '/boot/ksatflruxo', '/boot/ksxexbvwow', '/boot/kyjfilcrnq', '/boot/lgwpwkxyat', '/boot/ljmsrriafj', '/boot/lwhpfsdftn', '/boot/lwiovnycak', '/boot/lxwrjfjxtp', '/boot/lydfnrjaxp', '/boot/mfpmkpexoo', '/boot/mmyypjufxq', '/boot/nkoyupuxpx', '/boot/ogyujgrviy', '/boot/pxqgyrrbzu', '/boot/pyaqircmpc', '/boot/pydamssrzt', '/boot/pzjfoxtpmb', '/boot/qizzmavgpl', '/boot/qnztnkzxje', '/boot/qrwzvycybx', '/boot/rjvpbnmhxl', '/boot/rsztkcqmag', '/boot/surblktlmj', '/boot/tljpweugni', '/boot/vxcezwunnx', '/boot/xcyyuwgxmx', '/boot/yekbvdwwsw', '/boot/yterrxdnqm', '/boot/zdmysrquou', '/boot/zqghiflwfw', '/etc/cron.hourly/cron.sh', '/etc/crontab', '/etc/init.d/kyjfilcrnq', '/etc/perl/File/Glob.pm', '/etc/perl/File/Glob.pmc', '/etc/perl/XSLoader.pm', '/etc/perl/XSLoader.pmc', '/etc/perl/strict.pm', '/etc/perl/strict.pmc', '/etc/perl/warnings.pm', '/etc/perl/warnings.pmc', '/etc/rc.d/rc1.d/S90kyjfilcrnq', '/etc/rc.d/rc2.d/S90kyjfilcrnq', '/etc/rc.d/rc3.d/S90kyjfilcrnq', '/etc/rc.d/rc4.d/S90kyjfilcrnq', '/etc/rc.d/rc5.d/S90kyjfilcrnq', '/etc/rc1.d/S90kyjfilcrnq', '/etc/rc2.d/S90kyjfilcrnq', '/etc/rc3.d/S90kyjfilcrnq', '/etc/rc4.d/S90kyjfilcrnq', '/etc/rc5.d/S90kyjfilcrnq', '/etc/sed6bJvhB', '/etc/selinux/config', '/lib', '/prober', '/proc/1/root', '/proc/1521/exe', '/proc/rs_dev', '/proc/self/exe', '/proc/stat', '/proc/vz', '/run/systemd/system', '/run/systemd/system/', '/sbin/insserv', '/sbin/openrc', '/selinux', '/sys/fs/selinux', '/usr/local/share/perl/5.26.0', '/usr/local/share/perl/5.26.1/File/Glob.pm', '/usr/local/share/perl/5.26.1/File/Glob.pmc', '/usr/local/share/perl/5.26.1/XSLoader.pm', '/usr/local/share/perl/5.26.1/XSLoader.pmc', '/usr/local/share/perl/5.26.1/strict.pm', '/usr/local/share/perl/5.26.1/strict.pmc', '/usr/local/share/perl/5.26.1/warnings.pm', '/usr/local/share/perl/5.26.1/warnings.pmc', '/usr/share/perl/5.26/XSLoader.pm', '/usr/share/perl/5.26/XSLoader.pmc', '/usr/share/perl/5.26/strict.pm', '/usr/share/perl/5.26/strict.pmc', '/usr/share/perl/5.26/warnings.pm', '/usr/share/perl/5.26/warnings.pmc', '/usr/share/perl5/File/Glob.pm', '/usr/share/perl5/File/Glob.pmc', '/usr/share/perl5/XSLoader.pm', '/usr/share/perl5/XSLoader.pmc', '/usr/share/perl5/strict.pm', '/usr/share/perl5/strict.pmc', '/usr/share/perl5/warnings.pm', '/usr/share/perl5/warnings.pmc', '/var', '/var/run', '/var/run/sftp.pid', 'malware', 'uname']

process = ['/boot/auqrvglpdz', '/boot/awroivjpkx', '/boot/bkrlffbdxs', '/boot/bsthdzgvmt', '/boot/bsuztxmack', '/boot/bthcxsfqan', '/boot/btiipgrbod', '/boot/bxzcujmwuj', '/boot/culylmxbnn', '/boot/cuzvqbtvfd', '/boot/dczbbqscrr', '/boot/devawlqrit', '/boot/dgbfmcdgie', '/boot/eirlnrbbue', '/boot/fgqxqatvys', '/boot/frdsmulhvu', '/boot/ftrnncnlir', '/boot/fykepenmvn', '/boot/fzmicupinj', '/boot/gvqambdbei', '/boot/gzouwclwnr', '/boot/hbzgcgpgrl', '/boot/hlgpkoezsl', '/boot/hucenabudx', '/boot/iphpevdezt', '/boot/iswqwsprgu', '/boot/ixfnusqrgg', '/boot/jpyqhyfzey', '/boot/kfiegjyafw', '/boot/kfsglskbdb', '/boot/kkxlhyzfmp', '/boot/ksatflruxo', '/boot/ksxexbvwow', '/boot/kyjfilcrnq', '/boot/lgwpwkxyat', '/boot/ljmsrriafj', '/boot/lwhpfsdftn', '/boot/lwiovnycak', '/boot/lxwrjfjxtp', '/boot/lydfnrjaxp', '/boot/mfpmkpexoo', '/boot/mmyypjufxq', '/boot/nkoyupuxpx', '/boot/ogyujgrviy', '/boot/pxqgyrrbzu', '/boot/pyaqircmpc', '/boot/pydamssrzt', '/boot/pzjfoxtpmb', '/boot/qizzmavgpl', '/boot/qnztnkzxje', '/boot/qrwzvycybx', '/boot/rjvpbnmhxl', '/boot/rsztkcqmag', '/boot/surblktlmj', '/boot/tljpweugni', '/boot/vxcezwunnx', '/boot/xcyyuwgxmx', '/boot/yekbvdwwsw', '/boot/yterrxdnqm', '/boot/zdmysrquou', '/boot/zqghiflwfw', '1518', '1519', '1521', '1522', '1524', '1528', '1529', '1530', '1531', '1533', '1535', '1537', '1539', '1541', '1542', '1543', '1545', '1574', '1576', '1578', '1580', '1582', '1583', '1585', '1586', '1587', '1588', '1589', '1591', '1593', '1595', '1597', '1599', '1600', '1601', '1602', '1603', '1608', '1610', '1612', '1614', '1616', '1617', '1619', '1620', '1621', '1622', '1623', '1625', '1627', '1629', '1631', '1633', '1634', '1635', '1636', '1637', '1639', '1641', '1643', '1645', '1647', '1648', '1649', '1654', '1656', '1658', '1660', '1662', '1663', '1665', '1666', '1667', '1668', '1670', '1672', '1674', '1676', '1677', '1679', '1680', '1681', '1682', '1683', '1685', '1687', '1689', '1691', '1693', '1694', '1695', '1696', '1697', '1699', '1701', '1703', '1705', '1707', '1708', '1710', '1711', '1712', '1713', '1733', '1735', '1737', '1739', '1741', '1743', '1744', '1745', '1746', '1747', '1796', '1798', '1800', '1802', '1804', '1806', '1807', '1808', '1809', '1810', '1836', '1838', '1840', '1842', '1844', '1846', '1847', '1848', '1849', '1850', '1851', '1853', '1855', '1857', '1859', '1861', '1862', '1863', '1864', '1865', '1912', '1914', '1916', '1918', '1920', '1922', '1923', '1924', '1925', '1926', '1927', '1929', '1931', '1933', '1934', '1936', '1937', '1938', '1939', '1941', '1942', '1944', '1946', '1948', '1950', '1952', '1953', '1954', '1955', '1956', '1957', '1959', '1961', '1963', '1965', '1967', '1968', '1969', '1970', '1971', '1972', '1974', '1976', '1978', '1980', '1981', '1982', '1984', '1985', '1986', '1987', '1989', '1991', '1993', '1994', '1995', '1997', '1999', '2000', '2001', '2002', '2004', '2006', '2007', '2009', '2011', '2012', '2013', '2015', '2016', '2017', '2019', '2021', '2023', '2024', '2026', '2027', '2029', '2030', '2031', '2032', '2034', '2036', '2038', '2040', '2042', '2043', '2044', '2045', '2046', '2047', '2049', '2051', '2053', '2055', '2057', '2058', '2059', '2060', '2061', '2062', '2064', '2066', '2068', '2069', '2071', '2073', '2074', '2075', '2076', '2077', '2079', '2081', '2083', '2084', '2086', '2088', '2089', '2090', '2091', '2092', '2094', '2096', '2098', '2100', '2101', '2103', '2104', '2106', '2108', '2110', '2111', '2113', '2115', '2116', '2117', '2118', '2119', '2121', '2123', '2125', '2126', '2128', '2129', '2131', '2132', '2133', '2134', '2136', '2138', '2140', '2142', '2144', '2145', '2146', '2147', '2148', '2149', '2151', '2153', '2155', '2156', '2158', '2160', '2161', '2162', '2163', '2164', '2166', '2168', '2170', '2172', '2174', '2175', '2176', '2177', '2178', '2179', '2181', '2183', '2185', '2187', '2189', '2190', '2191', '2192', '2193', '2194', '2196', '2198', '2200', '2202', '2204', '2205', '2243', '2245', '2247', '2249', '2250', '2251', '2252', '2253', '2254', '2256', '2258', '2260', '2262', '2264', '2265', '2266', '2267', '2268', '2269', '2271', '2273', '2275', '2277', '2278', '2280', '2281', '2282', '2283', '2284', '2286', '2288', '2289', '2291', '2292', '2294', '2295', '2297', '2298', '2299', '2301', '2303', '2305', '2307', '2309', '2310', '2311', '2312', '2313', '2314', '2316', '2318', '2320', '2322', '2324', '2325', '2326', '2327', '2328', '2329', '2331', '2333', '2335', '2337', '2339', '2340', '2341', '2342', '2343', '2344', '2346', '2348', '2350', '2352', '2354', '2355', '2356', '2357', '2358', '2359', '2361', '2363', '2365', '2366', '2368', '2370', '2371', '2372', '2373', '2374', '2376', '2378', '2380', '2382', '2383', '2385', '2386', '2387', '2388', '2390', '2392', '2394', '2395', '2397', '2398', '2399', '2401', '2402', '2403', '2405', '2407', '2409', '2411', '2413', '2414', '2415', '2416', '2417', '2418', '2420', '2422', '2424', '2426', '2428', '2429', '2430', '2431', '2432', '2450', '2452', '2454', '2455', '2457', '2459', '2460', '2462', '2463', '2464', '2465', '2467', '2469', '2471', '2473', '2475', '2476', '2477', '2478', '2479', '2480', '2482', '2484', '2486', '2488', '2490', '2491', '2492', '2493', '2494', '2495', '2497', '2499', '2501', '2503', '2504', '2506', '2507', '2508', '2509', '2511', '2513', '2515', '2517', '2518', '2520', '2521', '2522', '2523', '2524', '2526', '2528', '2530', '2532', '2534', '2535', '2536', '2537', '2538', '2539', '2541', '2543', '2545', '2547', '2549', '2550', '2551', '2552', '2553', '2554', '2556', '2558', '2560', '2562', '2564', '2565', '2566', '2567', '2568', '2569', '2571', '2573', '2575', '2577', '2578', '2580', '2581', '2582', '2583', '2640', '2642', '2646', '2649', '2652', '2668', '2669', '2670', '2671', '2672', '2791', '2793', '2795', '2797', '2799', '2206', '2207', '2208', '2209', '2211', '2213', '2215', '2217', '2218', '2220', '2221', '2222', '2223', '2224', '2226', '2228', '2230', '2232', '2234', '2235', '2236', '2237', '2238', '2239', '2241', '2801', '2802', '2803', '2804', '2805', 'NO_PID', 'Pipe 3', 'Pipe 4', 'chkconfig', 'sed', 'sh', 'systemctl', 'update-rc.d']

net = ['0.0.0.0:80', '0.0.0.0:8005', '103.240.141.50:8005', '103.25.9.228:53', '103.25.9.245:8005', '66.102.253.30:8005', '8.8.8.8:53']

memory = ['Memory Address']

ID = ['UID:0', 'GID:0', 
'PID:1521', 'PID:1526', 'PID:1527', 'PID:1544',
'Shared Memory ID:2']

permission = ['Permission:022', 'Permission:0700']

time = ['Timestamp', 'Sleep duration'] # 不用 search

exit_status = ['status:0'] # 不用 search

resource_bytes = ['8192*1024 bytes'] # 不用 search

all_objects = file + process + net + memory + ID + permission


regex_file = {"sed command": ".*bin/sed", "startup": ["/etc/rc.*", "/etc/init.d/.*"],
			 "proc info":"/proc/.*", "sed temp file":"/etc/sed.*", "selinux":".*/selinux.*",
			 "boot":"/boot/.*", "rootkit component":"/proc/rs_dev",
			 "execution file created by xorddos":"/boot/[a-z]{10}", "run":["/run/.*", "/var/run/.*"],
			 "var": "/var/.*", "perl": ".*/perl/.*", "crontab": "/etc/cron.*",
			 "init process": ".*bin/openrc", "init service": ".*bin/insserv", "uname": "uname"}

regex_process = {"command": ["sed", "sh", "chkconfig", "systemctl", "update-rc.d"],
				"execution file created by xorddos": "/boot/[a-z]{10}", "pipe": "pipe.*",}

regex_net = {"ip":"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "port": [":\d{1,5}$", "port \d{1,5}$"],
				"ip + port": "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$"}

regex_mem = {"Memory Address": "0x[0-9a-zA-Z]{8}"}

regex_ID = {"UID": "UID.*", "GID": "GID.*"}

regex_permission = {"permission": "permission:{0,1}[0-9]{0,4}"}

all_regex_dict = {**regex_file,  **regex_process, **regex_net, **regex_mem, **regex_ID, **regex_permission}
all_regex_list = []

for v in all_regex_dict.values():
	if isinstance(v,list):
		for i in v:
			all_regex_list.append(i)
	else:
		all_regex_list.append(v)

### test 針對一個類別 ###

for f in file:
	for key in regex_file:
		rule = regex_file[key]
		if isinstance(rule, list):
			for r in rule:
				isMatch = re.match(r, f,)
				if isMatch:
					print("Match", key, ":", f)
		else:
			isMatch = re.match(rule, f)
			if isMatch:
				print("Match", key, ":", f)


### test 針對所有 ###
# for obj in all_objects:
#  	for regex in all_regex_list:
#  		isMatch = re.match(regex, obj)
#  		if isMatch:
#  			print("Match :", obj)
#  			break
