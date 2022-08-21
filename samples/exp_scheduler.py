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


normal = 0
wait_fast = 0
slow = 0

class ECNPolicy(SchedulerPolixy):
    mptcp_record_path = "/sys/fs/bpf/eMPTCP/mp_levelinfo"
    record_fd = bpf_obj_get(mptcp_record_path)

    class Flow: 
        def __init__(self, flow, rtt, cwnd, unacked):
            self.flow = flow 
            self.rtt = rtt 
            self.cwnd = cwnd 
            self.unacked = unacked 
            self.enable = cwnd > unacked  
        
        def __lt__(self, other) : 
            return self.rtt < other.rtt 


    def __init__(self):
        super().__init__()
        pass 

    def make(self, emptcp_connection):
        assert(isinstance(emptcp_connection, eMPTCPConnection) and "ECNPolicy Only support two subflow")
        if emptcp_connection.length() != 2: 
            return 10, emptcp_connection.remote_token, []
        
        flows = [] 
        for flow in emptcp_connection.flows():
            metric = self._get_subfflow_metrics(flow)
            print(metric)
            if metric == None: 
                return self._fail(emptcp_connection, "metric is None")
            flows.append(ECNPolicy.Flow(flow, metric[0], metric[1], metric[2]))
        
        if flows[0] < flows[1]:
            fast_flow = flows[0]
            slow_flow = flows[1]
        else:
            fast_flow = flows[1]
            slow_flow = flows[0]
        k_segment = self._get_connection_metric(emptcp_connection)
        print(k_segment)
        if k_segment == None: 
            self._fail("k_segment is None")
        
        #print metric info 
        print("k_segment :%d"%k_segment)
        print("fast_flow: %s"%self._strmetric(fast_flow))
        print("slow_flow: %s"%self._strmetric(slow_flow))
        print("normal: %d, wait_fast: %d, slow: %d"%(normal,wait_fast,slow))
        interal, actions = self._ECN_like_policy(k_segment, fast_flow, slow_flow)
        
        return interal, emptcp_connection.remote_token, actions

    def _get_subfflow_metrics(self, flow): 
        local_port = ntohs(flow[0])
        remote_port = ntohs(flow[1])
        local_addr =  int2ip(ntohl(flow[2]))
        remote_addr = int2ip(ntohl(flow[3]))
        ss_cmd = "ss -tim 'src {sI}:{sP} dst {dI}:{dP}'".format(sI = local_addr , sP = local_port, dI = remote_addr, dP = remote_port)
        result = os.popen(ss_cmd).readlines()[2].strip()
        #rto = float(re.findall("rto:\d+\.?\d*", result)[0].split(":")[1])
        rtt = re.findall("rtt:\d+\.?\d*", result)
        if len(rtt) == 0:
            rtt = 1000
        else:
            rtt = float(rtt[0].split(":")[1])
        cwnd = int(re.findall("cwnd:\d+", result)[0].split(":")[1])
        unacked = re.findall("unacked:\d+", result)
        if len(unacked) == 0:
            unacked = 0
        else: 
            unacked = int(unacked[0].split(":")[1])
        return rtt, cwnd, unacked

    def _get_connection_metric(self, emptcp_connection): 
        mptcp_key = ct.c_uint32(emptcp_connection.remote_token)
        wqueue = ct.c_uint32(0)
        try:
            bpf_map_lookup_elem(ECNPolicy.record_fd, ct.byref(mptcp_key), ct.byref(wqueue))
            return max(int(wqueue.value)//1460, 0)
        except Exception as e:
            print("get segment k error", e)
            return None 

    ##return actions 
    def _ECN_like_policy(self, k_segment, fast_f, slow_f): 
        if fast_f.enable:
            return self._normal_sub(fast_f, slow_f)
        n = 1 +  k_segment / fast_f.cwnd
        #if n * fast_f.rtt > slow_f.rtt and slow_f.enable and (k_segment / slow_f.cwnd) * slow_f.rtt < 2 * fast_f.rtt: 
        if n * fast_f.rtt > slow_f.rtt and slow_f.enable: 
            return self._use_slow_sub(fast_f, slow_f)
        else:
            return self._wait_fast_sub(fast_f, slow_f)

    def _strmetric(self, f):
        return "rtt: %f, cwnd: %d, unacked: %d"%(f.rtt, f.cwnd, f.unacked)

    def __normal_sub(self, fast_f, slow_f): 
        global normal 
        normal += 1
        slow_action = eMPTCPConnection.Action()
        slow_action.backup = False 
        slow_action.recover_flow = True 
        print("__normal") 
        return 1000 ,[(slow_f.flow, slow_action)]
    

    def __wait_fast_sub(self, fast_f, slow_f): 
        global wait_fast 
        wait_fast += 1
        slow_action = eMPTCPConnection.Action()
        slow_action.backup = True
        slow_action.recover_flow = False
        print("__wait fast subflow") 
        return 1000, [(slow_f.flow, slow_action)]

    def __use_slow_sub(self, fast_f, slow_f): 
        global slow
        slow += 1
        slow_action = eMPTCPConnection.Action()
        slow_action.backup = False 
        slow_action.recover_flow = True 
        print("__use slow subflow") 
        return 1000 , [(slow_f.flow, slow_action)]

    def _normal_sub(self, fast_f, slow_f): 
        global normal 
        normal += 1
        fast_action = eMPTCPConnection.Action()
        slow_action = eMPTCPConnection.Action()
        fast_action.recv_win_ingress = 40000
        slow_action.recv_win_ingress = 40000
        print("normal") 
        return 200 ,[(slow_f.flow, slow_action)]
    
    def _wait_fast_sub(self, fast_f, slow_f): 
        global wait_fast 
        wait_fast += 1
        fast_action = eMPTCPConnection.Action()
        slow_action = eMPTCPConnection.Action()
        fast_action.recv_win_ingress = 40000
        slow_action.recv_win_ingress = int(1 * slow_f.cwnd * 1460 //128)
        #slow_action.recv_win_ingress = 100
        print("wait fast subflow") 
        #return 100 ,[]
        return 300, [(slow_f.flow, slow_action)]

    def _use_slow_sub(self, fast_f, slow_f): 
        global slow
        slow += 1
        fast_action = eMPTCPConnection.Action()
        slow_action = eMPTCPConnection.Action()
        fast_action.recv_win_ingress = int(2 * fast_f.cwnd * 1460 //128)
        slow_action.recv_win_ingresss = 40000
        print("use slow subflow") 
        return 200 , [(slow_f.flow, slow_action)]


    def _fail(self, emptcp_connection, info = ""): 
        print("fail make policy %s"%info)
        return 10, emptcp_connection.remote_token, []

if __name__ == '__main__':
    setup_tc()
    SubflowInfo.setup()
    s = eMPTCPScheduler(ECNPolicy(), init_interval = 500)
    s.start()

'''
class TestSs(SchedulerPolixy):
    mptcp_k_path = "/sys/fs/bpf/eMPTCP/mp_levelinfo"
    k_fd = bpf_obj_get(mptcp_k_path)

    def __init__(self):
        super().__init__()
        pass 

    def make(self, emptcp_connection):
        assert(isinstance(emptcp_connection, eMPTCPConnection) and "ss make")
        now = round(time.time()*1000)
        
        # print(emptcp_connection.length())
        # print("make before")
        if emptcp_connection.length() != 2: 
            return 20, emptcp_connection.remote_token, []
        flow_v = []
        actions = []
        global count_s
        global count_f
        for key in emptcp_connection.flows():
            # print(key)
            local_port  = int.from_bytes(val_2_bytes(key[0], 2), byteorder = "big", signed = False)
            remote_port = int.from_bytes(val_2_bytes(key[1], 2), byteorder = "big", signed = False)
            local_addr  = int2ip(int.from_bytes(val_2_bytes(key[2], 4), byteorder = "big", signed = False))
            remote_addr = int2ip(int.from_bytes(val_2_bytes(key[3], 4), byteorder = "big", signed = False))
            cmd = "ss -tim 'src {sI}:{sP} dst {dI}:{dP}'".format(sI = local_addr , sP = local_port, dI = remote_addr, dP = remote_port)
            # print(local_addr,local_port,remote_addr,remote_port)
            # print(os.popen(cmd).readlines())
            result = os.popen(cmd).readlines()[2].strip()
            # print(result)
            rto = float(re.findall("rto:\d+\.?\d*", result)[0].split(":")[1])
            if rto != 1000:   
                rtt = float(re.findall(" rtt:\d+\.?\d*", result)[0].split(":")[1])
                # print("sucess2")
                cwnd = int(re.findall("cwnd:\d+\.?\d*", result)[0].split(":")[1])
                # print(flow_v)
                # print("cwnd:"+str(cwnd))
                flow_v.append((rtt, cwnd, emptcp_connection[key]))
            else:
                # actions.append((flow_v[0][2].flow, eMPTCPConnection.Action(65535)))
                # actions.append((emptcp_connection.__getitem__(key).flow, eMPTCPConnection.Action(1)))
                # count_f = count_f + 1
                # print("fast: %d" %count_f)
                # print("slow: %d" %count_s)
                # return 50, emptcp_connection.remote_token, actions
                return 20, emptcp_connection.remote_token, []
        # print(len(flow_v))
        # if len(flow_v) < 2:
        #     return 50, emptcp_connection.remote_token, []
        # print("success")
        # print(flow_v)
        global count_s
        global count_f

        k_ct = ct.c_uint32(0)
        t_ct = ct.c_uint32(emptcp_connection.remote_token)
        try:
            bpf_map_lookup_elem(TestSs.k_fd, ct.byref(t_ct), ct.byref(k_ct))
            k = max(k_ct.value//(1460*2) - 600, 0)
        except Exception:
            print("get k error")
            k = 0
        rtt1 = flow_v[0][0]
        cwnd1 = flow_v[0][1]
        info1 = flow_v[0][2]
        # print(info1.flow)
        rtt2 = flow_v[1][0]
        cwnd2 = flow_v[1][1]
        info2 = flow_v[1][2]
        print("k %d, cwnd1 %d, rtt1 %d, cwnd2 %d, rtt2 %d"%(k, cwnd1, rtt1, cwnd2, rtt2))
        # print(info2.flow)
        action1 = eMPTCPConnection.Action()
        action2 = eMPTCPConnection.Action()
        time_ret = 100 
        if rtt1 < rtt2:
            #print("use rtt1")
            t = rtt1 + (k/cwnd1)*rtt1
            if t < 2 * rtt2:
                recv_win1 = int((cwnd1 + 2*k) * 1460 /128 + 10000)
                #recv_win2 = int(1* cwnd2 * 1460 /128)
                #ecv_win2 = 1
                #recv_win1 = None 
                recv_win2 = None
                action1.recv_win_ingress = recv_win1
                action2.recv_win_ingress = recv_win2
                count_f = count_f + 1
                time_ret = t
                # print("fast")
            else:
                #recv_win1 = int(1 * cwnd1 * 1460 /128)
                recv_win1 = 30000
                recv_win2 = int((k//2 + cwnd2) * 1460 /128)
               # ecv_win2 = 1

                action1.recv_win_ingress = recv_win1
                action2.recv_win_ingress = recv_win2
                count_s = count_s + 1
                time_ret = 2 * rtt2
                # print("slow")                   
        else:
            #print("use rtt2")
            t = rtt2 + (k/cwnd2)*rtt2
            if t < 2 * rtt1:
                recv_win1 = int(1 * cwnd1 * 1460 /128)
                recv_win2 = int(3* cwnd2 * 1460 /128)
                action1.recv_win_ingress = recv_win1
                action2.recv_win_ingress = recv_win2
                count_f = count_f + 1
                # print("fast")
            else:
                recv_win1 = int(3* cwnd1 * 1460 /128)
                recv_win2 = int(1* cwnd2 * 1460 /128)
                action1.recv_win_ingress = recv_win1
                action2.recv_win_ingress = recv_win2
                count_s = count_s + 1
                # print("slow")

        actions.append((info1.flow, action1))
        actions.append((info2.flow, action2))
  
        print(recv_win1, recv_win2)
        end = round(time.time()*1000)
        print(end - now)
        print("fast:"+str(count_f))
        print("slow:"+str(count_s))
        # print("success")
        # print(" ")
        return time_ret, emptcp_connection.remote_token, actions
'''