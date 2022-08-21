#-*- coding:utf-8 -*-
import os 
import sys 
import re
from socket import ntohs, ntohl
import ctypes as ct 

PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(PROJECT_PATH,"./src/py/emptcp"))
from eMPTCP_scheduler import *
from utils import *
from libbpf import *
import socket as sk

# Policies 
class SubflowPolicy(SchedulerPolixy): 
    def __init__(self, recover_flow_time_ms):
        super().__init__()
        self.recover_flow_time_ms = recover_flow_time_ms
        #  flow = (tcp4.local_port, tcp4.remote_port, tcp4.local_addr, tcp4.remote_addr)
        self.subflow_backup_list = [(sk.htonl(ip2int("172.16.12.129")),sk.htonl(ip2int("172.16.12.132")))]  #local remot

    def make(self, emptcp_connection):
        assert(isinstance(emptcp_connection, eMPTCPConnection))
        actions = []
        now = round(time.time()*1000)
        a = eMPTCPConnection.Action()

        #interval = self.recover_flow_time_ms - (now - emptcp_connection.main_flow.start_us // 1000)
        interval = 20
        for info in emptcp_connection.infos():
            if (info.flow[2], info.flow[3]) not in  self.subflow_backup_list : 
                continue
            a = eMPTCPConnection.Action()
            #print(now - emptcp_connection.main_flow.start_us // 1000)
            if (now - emptcp_connection.main_flow.start_us // 1000) < self.recover_flow_time_ms :
                #set back up  
                print("set backup")
                a.backup = True 
                actions.append((info.flow, a))
            else: 
                #print("set recover")
                if info.action.backup == True :
                    print("recover")
                    a.backup = False 
                    a.recover_flow = True 
                    actions.append((info.flow, a))
        return interval, emptcp_connection.remote_token, actions
    

if __name__ == '__main__':
    setup_tc()
    SubflowInfo.setup()
    s = eMPTCPScheduler(SubflowPolicy(1000))
    s.un_sock = setup_unsock()
    s.start()
    s.un_sock.close()

    for pkt in pkt_list:
        pkt.show2()