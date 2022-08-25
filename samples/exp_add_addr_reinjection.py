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

# Policies 
class AddAddrPolicy(SchedulerPolixy): 
    def __init__(self, recover_time_ms):
        super().__init__()
        self.recover_time_ms = recover_time_ms
        pass 

    def make(self, emptcp_connection):
        assert(isinstance(emptcp_connection, eMPTCPConnection))
        print("make")
        actions = []
        now = round(time.time()*1000)
        a = eMPTCPConnection.Action()
        interval = 100
        if now - emptcp_connection.main_flow.start_us // 1000 < self.recover_time_ms:
            print("rm_add_addr")
            #after 10 milliseconds 
            a.rm_add_addr = True 
            a.recover_add_addr = False 
            interval = self.recover_time_ms - (now - emptcp_connection.main_flow.start_us // 1000)
        else: 
            a.rm_add_addr = False
            if len(emptcp_connection.add_addr_opt_list) > 0:
                print("recover_add_addr")
                a.recover_add_addr = True 
            else:
                print("can't recover_add_addr")
                a.recover_add_addr = False
        actions.append((emptcp_connection.main_flow.flow, a))
        return interval, emptcp_connection.remote_token, actions
        #return interval, emptcp_connection.remote_token, []


if __name__ == '__main__':
    setup_tc()
    SubflowInfo.setup()
    s = eMPTCPScheduler(AddAddrPolicy(10), init_interval = 0)
    s.un_sock = setup_unsock()
    s.start()
    s.un_sock.close()
    for pkt in pkt_list:
        pkt.show2()
