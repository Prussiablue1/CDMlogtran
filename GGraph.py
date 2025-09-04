import json
import uuid
import time
import os

class MyGraph:
    def __init__(self, name=None):
        self.name = name
        self.nodes = {}   # {node: {属性字典}}
        self.edges = {}   # {(u, v): [{属性字典}, ...]}  # 多重边

    def has_node(self, node):
        return node in self.nodes

    def add_node(self, node, **attrs):
        if node not in self.nodes:
            self.nodes[node] = {}
        self.nodes[node].update(attrs)



    def has_edge(self, u, v, **match_attrs):
        attr_list = self.edges.get((u, v), [])
        if not match_attrs:
            return bool(attr_list)
        for attrs in attr_list:
            if all(attrs.get(k) == val for k, val in match_attrs.items()):
                return True
        return False


    def add_edge(self, u, v, **attrs):
        if not self.has_node(u):
            self.add_node(u)
        if not self.has_node(v):
            self.add_node(v)

        if (u, v) not in self.edges:
            self.edges[(u, v)] = []
        self.edges[(u, v)].append(attrs)

    







    def export_cdm(self, out_dir="./output"):
        """导出为 CDM JSON，分为 nodes.json 和 events.json"""
        node_objs = []
        event_objs = []

        os.makedirs(out_dir, exist_ok=True)



        # === 节点导出 ===
        for node, attrs in self.nodes.items():
            node_type = attrs.get("type", "Unknown")
            ts = int(attrs.get("timestamp", time.time())) * 1_000_000_000  # 纳秒
            node_uuid = str(uuid.uuid4())
            attrs["_uuid"] = node_uuid  # 存到属性里，方便边引用

            if node_type == "domain_name" :
                obj = {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.FileObject": {
                            "uuid": node_uuid,
                            "predicateObjectPath": node
                        }
                    }
                }

            elif node_type == "IP_Address":
                obj = {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                            "uuid": node_uuid,
                            "localAddress": None,       # 如果你没有本地 IP，可填 None
                            "localPort": None,          # 如果没有本地端口，可填 None
                            "remoteAddress": node, # IP 地址放到 remoteAddress
                            "remotePort": None,         # 如果没有远程端口，可填 None
                        }
                    }
                }

            elif node_type == "web_object":
                obj = {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.FileObject": {
                            "uuid": node_uuid,
                            "predicateObjectPath": node
                        }
                    }
                }
            
            elif node_type == "process":
                obj = {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.Subject": {
                            "uuid": node_uuid,
                            "exec": node
                        }
                    }
                }

            elif node_type == "file":
                obj = {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.FileObject": {
                            "uuid": node_uuid,
                            "predicateObjectPath": node
                        }
                    }
                }

            elif node_type == "connection":
                # joint_ips 格式: connection_192.168.0.10_203.0.113.45
                parts = node.split("_")
                if len(parts) >= 3:
                    local_ip = parts[1]
                    remote_ip = parts[2]
                else:
                    local_ip = None
                    remote_ip = None

                obj = {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                            "uuid": node_uuid,
                            "localAddress": local_ip,       
                            "localPort": None,              
                            "remoteAddress": remote_ip,     
                            "remotePort": None,             
                        }
                    }
                }
            
            elif node_type == "session":
                # 从节点属性中取出IP和端口
                ip = attrs.get("ip")
                port = attrs.get("port")
                flag = attrs.get("flag")  # 0 或 1

                # 根据命名区分 sender/receiver
                if flag == 0:
                    obj = {
                        "datum": {
                            "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                "uuid": node_uuid,
                                "localAddress": None,       
                                "localPort": None,          
                                "remoteAddress": ip,     
                                "remotePort": port,             
                            }
                        }
                    }
                else:
                    obj = {
                        "datum": {
                            "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                "uuid": node_uuid,
                                "localAddress": ip,       
                                "localPort": port,          
                                "remoteAddress": None,     
                                "remotePort": None,             
                            }
                        }
                    }





            else:
                pass  # 其他类型节点的处理逻辑

            node_objs.append(obj)









        # === 边导出 ===
        for (u, v), attr_list in self.edges.items():
            for edge_attrs in attr_list:
                ts = int(edge_attrs.get("timestamp", time.time())) * 1_000_000_000
                edge_uuid = str(uuid.uuid4())
                edge_type = edge_attrs.get("type", "Unknown")

                if edge_type == "resolve":
                    edge_type = "EVENT_OTHER"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }
                    
                elif edge_type == "web_request":
                    edge_type = "EVENT_SENDTO"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }
                    
                elif edge_type == "refer":
                    edge_type = "EVENT_FLOWS_TO"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        } 

                elif edge_type == "executed":
                    edge_type = "EVENT_EXECUTE"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.Subject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        } 

                elif edge_type == "fork":
                    edge_type = "EVENT_FORK"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.Subject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.Subject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        } 
                    
                elif edge_type == "connected_remote_ip":
                    edge_type = "EVENT_CONNECT"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    v_type = self.nodes[v].get("type", "")
                    if v_type == "process":
                        predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.Subject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }
                    else:
                        predicate_json  = {
                                "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                    "uuid": self.nodes[v]["_uuid"]
                                }
                            } 
                        
                elif edge_type == "connect":
                    edge_type = "EVENT_CONNECT"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.Subject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }
                    
                elif edge_type == "sock_send":
                    edge_type = "EVENT_SENDMSG"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }
                


                elif edge_type == "bind":
                    edge_type = "EVENT_BIND"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.Subject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }
                
                elif edge_type == "connected_session":
                    edge_type = "EVENT_CONNECT"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.NetFlowObject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }
                
                
                


                elif edge_type == "read":
                    edge_type = "EVENT_READ"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.Subject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }
                
                elif edge_type == "write":
                    edge_type = "EVENT_WRITE"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.Subject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }
                elif edge_type == "delete":
                    edge_type = "EVENT_UNLINK"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.Subject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }
                elif edge_type == "execute":
                    edge_type = "EVENT_EXECUTE"
                    subject_json = {
                            "com.bbn.tc.schema.avro.cdm18.Subject": {
                                "uuid": self.nodes[u]["_uuid"]
                            }
                        }
                    predicate_json  = {
                            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                                "uuid": self.nodes[v]["_uuid"]
                            }
                        }




                obj = {
                    "datum": {
                        "com.bbn.tc.schema.avro.cdm18.Event": {
                            "uuid": edge_uuid,
                            "type": edge_type,
                            "timestampNanos": ts,
                            "subject": subject_json,
                            "predicateObject": predicate_json
                        }
                    }
                }
                event_objs.append(obj)






        # === 写文件 ===
        with open(os.path.join(out_dir, "nodes.json"), "w", encoding="utf-8") as f:
            json.dump(node_objs, f, indent=2, ensure_ascii=False)

        with open(os.path.join(out_dir, "events.json"), "w", encoding="utf-8") as f:
            json.dump(event_objs, f, indent=2, ensure_ascii=False)

        print(f"✅ Exported {len(node_objs)} nodes and {len(event_objs)} events to '{out_dir}'")
