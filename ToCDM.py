import networkx as nx
import matplotlib.pyplot as plt
import os
import re
import time
import GGraph

processes = {}
lines = []
hosts_ips = []
G = None


def construct_G(IncludeExecutedEdges=True, StartTime=0):
    global lines, G
    G = GGraph.MyGraph(name="CDM_Graph")

    # 遍历日志行
    for line in lines:
        if "FMfcgxvzKb" in line:
            print(line)
        line = line.lower().replace("\\", "/")
        splitted_line = line.split(",")
        if len(splitted_line) < 15:
            continue

        
        # DNS
        # timestamp,q_domain,r_ip,,,,,,,,,,,,,,,,,-LD-
        if len(splitted_line[1]) > 0 and len(splitted_line[2]) > 0:
            edge_type = "resolve"
            edge_label = edge_type + "_" + str(splitted_line[0])
            domain_name = splitted_line[1]
            IP_Address = splitted_line[2] #.replace(":", "_")
            if int(splitted_line[0]) >= StartTime:
                if not G.has_node(domain_name):
                    G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
                if not G.has_node(IP_Address):
                    G.add_node(IP_Address, type="IP_Address", timestamp=splitted_line[0])
                if not G.has_edge(domain_name, IP_Address):
                    G.add_edge(domain_name, IP_Address, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
        






        # HTTP 
        # web_object to domain_name (in referal)
        # timestamp,,,,,,,,,http_type,req_url,post_url,res_code,host,referer,location,,,,-LB-
        if len(splitted_line[15]) > 0 and not splitted_line[15].startswith("/"): #  and not splitted_line[15].startswith("/") and "/" in splitted_line[15]
            # 检查第 15 列是否非空，并且不是以 / 开头。
            edge_type = "web_request"
            domain_name = splitted_line[15]

            if ":" in domain_name:
                domain_name = domain_name.split(":")[0]
            if "://" in domain_name:
                domain_name = domain_name.split("://")[1]
            if "/" in domain_name:
                domain_name = domain_name[:domain_name.find("/")]

            web_object = splitted_line[15] # .replace(":", "_")
            if not "/" in web_object:
                web_object += "/"
            if "//" in web_object:
                web_object = web_object.replace("//", "/")
            # 给边打上标签，比如：web_request_26520345。
            edge_label = edge_type + "_" + str(splitted_line[0])

            if int(splitted_line[0]) >= StartTime:
                if not G.has_node(domain_name):
                    G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
                if not G.has_node(web_object):
                    G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
                if not G.has_edge(web_object, domain_name):
                    G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])


        # HTTP 
        # web_object to domain_name
        if len(splitted_line[14]) > 0:
            edge_type = "web_request"
            domain_name = splitted_line[14]
            if ":" in domain_name:
                domain_name = domain_name[:domain_name.find(":")]
            if "/" in domain_name:
                domain_name = domain_name[:domain_name.find("/")]
            
            # 构造 web_object
            web_object = splitted_line[14]
            if not "/" in web_object:
                web_object += "/"

            # 接着根据 请求 URL（req_url） 或 响应 URL（post_url） 来更新：
            web_object = web_object # .replace(":", "_")
            if len(splitted_line[11]) > 0:
                url = splitted_line[11] # .replace(":", "_")
                if url.startswith("/"):
                    web_object = splitted_line[14] + url # .replace(":", "_") splitted_line[14].replace(":", "_") 
                else:
                    #web_object = splitted_line[14].replace(":", "_") + "/" + url.replace(":", "_")
                    web_object = splitted_line[11] # .replace(":", "_")
            elif len(splitted_line[12]) > 0:
                url = splitted_line[12]
                if url.startswith("/"):
                    web_object = splitted_line[14] + url # .replace(":", "_") splitted_line[14].replace(":", "_")
                else:
                    #web_object = splitted_line[14].replace(":", "_") + "/" + url.replace(":", "_")
                    web_object = splitted_line[12] # .replace(":", "_")
            
            web_object = web_object.replace("//", "/")

            # 构建 web_object → domain_name
            edge_label = edge_type + "_" + str(splitted_line[0])
            if int(splitted_line[0]) >= StartTime:
                if not G.has_node(domain_name):
                    G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
                if not G.has_node(web_object):
                    G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
                if not G.has_edge(web_object, domain_name):
                    G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
            
            # web_object (from referal) to web_object in request/response
            # 构建 refer 边（来源 URL → 当前 URL）
            if len(splitted_line[15]) > 0:
                edge_type = "refer"
                edge_label = edge_type + "_" + str(splitted_line[0])
                web_object0 = splitted_line[15] # .replace(":", "_")
                if int(splitted_line[0]) >= StartTime:
                    if not G.has_node(web_object0):
                        G.add_node(web_object0, type="web_object", timestamp=splitted_line[0])
                    if not G.has_node(web_object):
                        G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
                    if not G.has_edge(web_object, web_object0):
                        G.add_edge(web_object, web_object0, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
            


        # HTTP 
        # POST web_object to domain_name
        # 检查 POST URL 是否存在
        elif len(splitted_line[12]) > 0:
            IsValidIP = False
            cleaned_ip = ""
            edge_type = "web_request"
            edge_label = edge_type + "_" + str(splitted_line[0])

            # 处理 domain_name
            domain_name = splitted_line[14]
            if not ":" in domain_name:
                IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name)
                if IsValidIP:
                    cleaned_ip = domain_name
                    domain_name += "_website"
            else:
                IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name.split(":")[0])
                if IsValidIP:
                    cleaned_ip = domain_name.split(":")[0]
                    domain_name = domain_name.split(":")[0] + "_website_" + domain_name.split(":")[1]
                else:
                    domain_name = domain_name # .replace(":", "_")
            if "/" in domain_name:
                domain_name = domain_name[:domain_name.find("/")]

            # 构造 web_object
            web_object = domain_name + splitted_line[12]
            if not "/" in web_object:
                web_object += "/"

            # 添加图节点和边 (POST 请求)
            if int(splitted_line[0]) >= StartTime:
                if not G.has_node(domain_name):
                    G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
                if not G.has_node(web_object):
                    G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
                if not G.has_edge(web_object, domain_name):
                    G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])

                # 解析 IP 地址 (resolve 边)
                if IsValidIP:
                    edge_type = "resolve"
                    edge_label = edge_type + "_" + str(splitted_line[0])
                    if not G.has_node(cleaned_ip):
                        G.add_node(cleaned_ip, type="IP_Address", timestamp=splitted_line[0])
                    if not G.has_edge(domain_name, cleaned_ip):
                        G.add_edge(domain_name, cleaned_ip, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])

            # 处理 Referer (第 15 列)
            if len(splitted_line[15]) > 0:
                IsValidIP = False
                cleaned_ip = ""
                edge_type = "refer"
                edge_label = edge_type + "_" + str(splitted_line[0])
                domain_name = splitted_line[15]
                if not ":" in domain_name:
                    IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name)
                    if IsValidIP:
                        cleaned_ip = domain_name
                        domain_name += "_website"
                else:
                    IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name.split(":")[0])
                    if IsValidIP:
                        cleaned_ip = domain_name.split(":")[0]
                        domain_name = domain_name.split(":")[0] + "_website_" + domain_name.split(":")[1]
                    else:
                        domain_name = domain_name # .replace(":", "_")
    
                if "/" in domain_name:
                    domain_name = domain_name[:domain_name.find("/")]
    
                if int(splitted_line[0]) >= StartTime:
                    if not G.has_node(domain_name):
                        G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
                    if not G.has_node(web_object):
                        G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
                    if not G.has_edge(web_object, domain_name):
                        G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
                    if IsValidIP:
                        edge_type = "resolve"
                        edge_label = edge_type + "_" + str(splitted_line[0])
                        if not G.has_node(cleaned_ip):
                            G.add_node(cleaned_ip, type="IP_Address", timestamp=splitted_line[0])
                        if not G.has_edge(domain_name, cleaned_ip):
                            G.add_edge(domain_name, cleaned_ip, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])


        # HTTP 
        # GET
        elif len(splitted_line[11]) > 0:
            IsValidIP = False
            cleaned_ip = ""
            edge_type = "web_request"
            edge_label = edge_type + "_" + str(splitted_line[0])
        
            # 处理 domain_name
            domain_name = splitted_line[11]
            if not "/" in splitted_line[11]:
                domain_name = splitted_line[11]
            else:
                domain_name = splitted_line[11][:splitted_line[11].find("/")]
            
            if not ":" in domain_name:
                IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name)
                if IsValidIP:
                    cleaned_ip = domain_name
                    domain_name += "_website"
            else:
                IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name.split(":")[0])
                if IsValidIP:
                    cleaned_ip = domain_name.split(":")[0]
                    domain_name = domain_name.split(":")[0] + "_website_" + domain_name.split(":")[1]
                else:
                    domain_name = domain_name # .replace(":", "_")

            if "/" in domain_name:
                domain_name = domain_name[:domain_name.find("/")]


            # 构造 web_object
            web_object = domain_name + splitted_line[11][splitted_line[11].find("/"):] # .replace(":", "_")
            if not "/" in web_object:
                web_object += "/"

            # 加入图 (GET 请求)
            if int(splitted_line[0]) >= StartTime:
                if not G.has_node(domain_name):
                    G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
                if not G.has_node(web_object):
                    G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
                if not G.has_edge(web_object, domain_name):
                    G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])

                # 如果 host 是 IP，加上 resolve
                if IsValidIP:
                    edge_type = "resolve"
                    edge_label = edge_type + "_" + str(splitted_line[0])
                    if not G.has_node(cleaned_ip):
                        G.add_node(cleaned_ip, type="IP_Address", timestamp=splitted_line[0])
                    if not G.has_edge(domain_name, cleaned_ip):
                        G.add_edge(domain_name, cleaned_ip, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])

            # Referer 处理 (第 15 列)
            if len(splitted_line[15]) > 0:
                IsValidIP = False
                cleaned_ip = ""
                edge_type = "refer"
                edge_label = edge_type + "_" + str(splitted_line[0])
                domain_name = splitted_line[15]
                if not ":" in domain_name:
                    IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name)
                    if IsValidIP:
                        cleaned_ip = domain_name
                        domain_name += "_website"
                else:
                    IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name.split(":")[0])
                    if IsValidIP:
                        cleaned_ip = domain_name.split(":")[0]
                        domain_name = domain_name.split(":")[0] + "_website_" + domain_name.split(":")[1]
                    else:
                        domain_name = domain_name  # .replace(":", "_")
    
                if "/" in domain_name:
                    domain_name = domain_name[:domain_name.find("/")]
    
                if int(splitted_line[0]) >= StartTime:
                    if not G.has_node(domain_name):
                        G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
                    if not G.has_node(web_object):
                        G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
                    if not G.has_edge(web_object, domain_name):
                        G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
                    if IsValidIP:
                        edge_type = "resolve"
                        edge_label = edge_type + "_" + str(splitted_line[0])
                        if not G.has_node(cleaned_ip):
                            G.add_node(cleaned_ip, type="IP_Address", timestamp=splitted_line[0])
                        if not G.has_edge(domain_name, cleaned_ip):
                            G.add_edge(domain_name, cleaned_ip, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])







        # audit log  
        # timestamp,,,pid,ppid,pname,s_ip,s_port,d_ip,d_port,,,,,,,,acct,objname,network_direction,-LA-
        if len(splitted_line[3]) > 0:
            # create the current line process
            # 提取 PID 和程序名
            pid = splitted_line[3]
            program_name = splitted_line[5]
            node_name = program_name + "_" + pid

            # 处理缺失字段
            if len(program_name) == 0 or len(pid) == 0:
                if len(pid) == 0:
                    pid = "NOPID"
                if len(program_name) == 0:
                    program_name = "NOPROCESSNAME"
                node_name = program_name + "_" + pid
            else:
                processes[pid] = program_name
            node_name = str(node_name)
            
            # 标准化路径
            if program_name.startswith("/device/harddiskvolume1"):
                program_name = program_name.replace("/device/harddiskvolume1", "c:")
                node_name = node_name.replace("/device/harddiskvolume1", "c:")
            
            if not G.has_node(node_name) and not node_name == "NOPROCESSNAME" and not node_name == "NOPROCESSNAME_NOPID":
                #print node_name
                if int(splitted_line[0]) >= StartTime:
                    # 添加进程节点
                    G.add_node(node_name, type="process", timestamp=splitted_line[0])
                    if program_name.endswith("/") and not program_name.endswith("//"):
                        program_name = program_name[:len(program_name)-1] + "//"
                    if not program_name == "NOPROGRAMNAME":
                        program_name = program_name.rstrip()
                        # 添加文件节点（程序本身）
                        if not G.has_node(program_name):
                            G.add_node(program_name, type="file", timestamp=splitted_line[0])
                        # 连接边
                        if IncludeExecutedEdges:
                            edge_type = "executed"
                            edge_label = edge_type + "_" + str(0)
                            G.add_edge(node_name, program_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
            

            
            # create a direct edge from parent to current line process
            # 父子进程关系（fork 关系）
            if len(splitted_line[4]) > 0:
                # 检查 parent PID
                parent_node_name = ""
                parent_pid = splitted_line[4]
                parent_name = ""
                if parent_pid in processes.keys():
                    parent_name = processes[parent_pid]
                else:
                    parent_name = "NOPROCESSNAME"
                parent_node_name = parent_name + "_" + parent_pid
                parent_node_name = str(parent_node_name)

                # 处理路径
                if parent_node_name.startswith("/device/harddiskvolume1"):
                    parent_name = parent_name.replace("/device/harddiskvolume1", "c:")
                    parent_node_name = parent_node_name.replace("/device/harddiskvolume1", "c:")
                
                # 添加父进程节点和父程序节点
                if not G.has_node(parent_node_name) and not parent_node_name == "NOPROCESSNAME" and not parent_node_name == "NOPROCESSNAME_NOPID":
                    if int(splitted_line[0]) >= StartTime:
                        G.add_node(parent_node_name, type="process", timestamp=splitted_line[0])
                        if not parent_name == "NOPROCESSNAME":
                            if not G.has_node(parent_name):
                                if parent_name.endswith("/"):
                                    parent_name = parent_name[:len(parent_name)-1] + "//"
                                G.add_node(parent_name, type="file", timestamp=splitted_line[0])
                            if IncludeExecutedEdges:
                                edge_type = "executed"
                                edge_label = edge_type + "_" + str(0)
                                G.add_edge(parent_node_name, parent_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
                
                # 添加 fork 边  Notice: 是 当前节点 → 父节点，与一般 父 → 子 不一样
                # ！！！大修过            
                edge_type = "fork"
                edge_label = edge_type + "_" + str(splitted_line[0])    
                if int(splitted_line[0]) >= StartTime:
                    # 先检查边是否已经存在
                    already_added = False
                    edge_key = (node_name, parent_node_name)
                    if edge_key in G.edges:
                        for edge_attrs in G.edges[edge_key]:
                            if edge_attrs.get('type', '') == edge_type:
                                already_added = True
                                break
                    if not already_added:
                        # 如果不存在就添加边
                        G.add_edge(node_name, parent_node_name, capacity=1.0, label=edge_label, type=edge_type, timestamp=splitted_line[0])




            # 网络连接信息
            if len(splitted_line[8]) > 0:
                # 提取源、目的 IP 和端口
                d_ip = splitted_line[8]
                d_port = str(0)
                if len(splitted_line[9]) > 0:
                    d_port = splitted_line[9]
                d_ip = d_ip # .replace(":", "_")
                s_ip = splitted_line[6]
                s_port = str(0)
                if len(splitted_line[7]) > 0:
                    s_port = splitted_line[7]
    
                s_ip = s_ip # .replace(":", "_")

                # 构造连接节点
                joint_ips = ""
                joint_ips1 = s_ip + "_" + d_ip
                joint_ips2 = d_ip + "_" + s_ip

                if not G.has_node(joint_ips1) and not G.has_node(joint_ips2):
                    if int(splitted_line[0]) >= StartTime:
                        joint_ips = "connection_" + joint_ips1
                        G.add_node(joint_ips, type="connection", timestamp=splitted_line[0])
                else:
                    if G.has_node(joint_ips1):
                        if int(splitted_line[0]) >= StartTime:
                            joint_ips = joint_ips1
                    else:
                        if int(splitted_line[0]) >= StartTime:
                            joint_ips = joint_ips2               

                # 添加 IP 节点
                if not G.has_node(s_ip):
                    if int(splitted_line[0]) >= StartTime:
                        G.add_node(s_ip, type="IP_Address", timestamp=splitted_line[0])
                if not G.has_node(d_ip):
                    if int(splitted_line[0]) >= StartTime:
                        G.add_node(d_ip, type="IP_Address", timestamp=splitted_line[0])

                # 连接远程 IP 与进程 / 连接节点
                # this block is to connect the remote IP to process, joint_ips connection and local ports
                edge_type = "connected_remote_ip"
                edge_label = edge_type + "_" + str(splitted_line[0])
                if int(splitted_line[0]) >= StartTime:
                    if s_ip == hosts_ips[0]: #if s_ip == "0.0.0.0" or s_ip == "127.0.0.1" or 
                        if not G.has_edge(d_ip, node_name): # .encode('unicode_escape')
                            G.add_edge(d_ip, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=d_ip)
                        if not G.has_edge(d_ip, joint_ips): # .encode('unicode_escape')
                            G.add_edge(d_ip, joint_ips, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=d_ip)
                    elif d_ip == hosts_ips[0]:
                        if not G.has_edge(s_ip, node_name): # .encode('unicode_escape')
                            G.add_edge(s_ip, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=s_ip)
                        if not G.has_edge(s_ip, joint_ips): # .encode('unicode_escape')
                            G.add_edge(s_ip, joint_ips, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=s_ip)
                
                
                # 连接节点 → 进程（连接边）
                edge_type = "connect"
                edge_label = edge_type + "_" + str(splitted_line[0])
                if int(splitted_line[0]) >= StartTime:
                    if not G.has_edge(joint_ips, node_name): # .encode('unicode_escape')
                        G.add_edge(joint_ips, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], sip=s_ip, sport=s_port, dip=d_ip, dport=d_port)
                    else:
                        ALREADY_ADDED = False
                        for attrs in G.edges[(joint_ips, node_name)]:
                            if (attrs.get('type') == edge_type and
                                attrs.get('sip') == s_ip and
                                attrs.get('sport') == s_port and
                                attrs.get('dip') == d_ip and
                                attrs.get('dport') == d_port):
                                ALREADY_ADDED = True
                                break
                        if not ALREADY_ADDED:
                            G.add_edge(joint_ips, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], sip=s_ip, sport=s_port, dip=d_ip, dport=d_port)
                

                # sock_send 创建会话节点，并连接会话与进程  receiver → sender
                edge_type = "sock_send"
                edge_label = edge_type + "_" + str(splitted_line[0])
                sender = "session_"+s_ip+"_"+s_port
                if not G.has_node(sender):
                    if int(splitted_line[0]) >= StartTime:
                        G.add_node(sender, type="session", timestamp=splitted_line[0], ip=s_ip, port=s_port,flag=1)
                
                receiver = "session_"+d_ip+"_"+d_port
                if not G.has_node(receiver):
                    if int(splitted_line[0]) >= StartTime:
                        G.add_node(receiver, type="session", timestamp=splitted_line[0], ip=d_ip, port=d_port,flag=0)

                if not G.has_edge(receiver, sender): # .encode('unicode_escape')
                    G.add_edge(receiver, sender, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], sip=s_ip, sport=s_port, dip=d_ip, dport=d_port)
                

                # bind / connected_session 边
                edge_type = "bind"
                edge_label = edge_type + "_" + str(splitted_line[0])

                if s_ip == hosts_ips[0]: #s_ip == "0.0.0.0" or s_ip == "127.0.0.1" or 
                    if not G.has_edge(sender, node_name): # .encode('unicode_escape')
                        G.add_edge(sender, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=s_ip, port=s_port)
                    edge_type = "connected_session"
                    edge_label = edge_type + "_" + str(splitted_line[0])
                    if not G.has_edge(d_ip, sender): # .encode('unicode_escape')
                        G.add_edge(d_ip, sender, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=s_ip, port=s_port)
                elif d_ip == hosts_ips[0]:
                    if not G.has_edge(receiver, node_name): # .encode('unicode_escape')
                        G.add_edge(receiver, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=d_ip, port=d_port)
                    edge_type = "connected_session"
                    edge_label = edge_type + "_" + str(splitted_line[0])
                    if not G.has_edge(s_ip, receiver): # .encode('unicode_escape')
                        G.add_edge(s_ip, receiver, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=d_ip, port=d_port)
        



            # 文件操作事件处理
            if len(splitted_line[17]) > 0 and splitted_line[17].startswith("file_") and len(splitted_line[18]) > 0:
                # 条件筛选文件操作
                accesses = splitted_line[17].rstrip()
                file_name = splitted_line[18].rstrip()

                # 添加文件节点
                if int(splitted_line[0]) >= StartTime:
                    if not G.has_node(file_name):
                        if file_name.endswith("/") and not file_name.endswith("//"):
                            file_name = file_name[:len(file_name)-1] + "//"
                        G.add_node(file_name, type="file", timestamp=splitted_line[0])

                # 构建文件操作边
                for edge_type in ["readdata", "write", "delete", "execute"]: #"readdata", "writedata"
                    src_node = file_name
                    dst_node = node_name
                    if edge_type in accesses and not "attribute" in accesses: 
                        # 调整边方向
                        if edge_type == "readdata":
                            edge_type = "read"
                        if edge_type == "write":
                            edge_type = "write"
                        edge_label = edge_type + "_" + str(splitted_line[0])

                        #"execute" is not like fork, it is more like read, as it goes for every
                        #module gets executed under every process that executes that module.
                        if edge_type == "read" or edge_type == "execute": # 
                            src_node = node_name
                            dst_node = file_name

                        # 添加边，防止重复
                        if int(splitted_line[0]) >= StartTime:
                            if not G.has_edge(src_node, dst_node): # .encode('unicode_escape')
                                G.add_edge(src_node, dst_node, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
                            else:
                                ALREADY_ADDED = False
                                for attrs in G.edges.get((src_node, dst_node), []):
                                    if attrs['label'].startswith(edge_type):
                                        ALREADY_ADDED = True
                                        break
                                if not ALREADY_ADDED:
                                    G.add_edge(src_node, dst_node, capacity=1.0, label=edge_label, type=edge_type, timestamp=splitted_line[0])

    G.export_cdm()




def load_hosts_ips(file):
    global hosts_ips

    hosts_ips = []
    training_prefix = "training_preprocessed_logs_"
    testing_prefix = "testing_preprocessed_logs_"

    if training_prefix in file:
        logs_folder = file.split(training_prefix)[1]#[:-3]
    if testing_prefix in file:
        logs_folder = file.split(testing_prefix)[1]#[:-3]


    if file.startswith(training_prefix):
        ip_file = open("training_logs/" + logs_folder + "/ips.txt")
        hosts_ips = ip_file.readlines()
        
    if file.startswith(testing_prefix):
        ip_file = open("testing_logs/" + logs_folder + "/ips.txt")
        hosts_ips = ip_file.readlines()
    

    for ip in range(0, len(hosts_ips)):
        hosts_ips[ip] = hosts_ips[ip].lower().rstrip()





if __name__ == "__main__":
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input")  # 指定 output 文件夹
    for file in os.listdir(base_dir):
        if file.startswith("training_preprocessed_logs") or file.startswith("testing_preprocessed_logs"):
            file_path = os.path.join(base_dir, file)
            print(f"Processing file: {file}")

            with open(file_path, "r", encoding="utf-8") as log_file:
                load_hosts_ips(file)   # 传文件名，函数里会区分 train/test
                print(hosts_ips)

                processes = {}
                lines = log_file.readlines()
                G = None

                construct_G()

            print(f"Finished processing file: {file}\n")



