#-*- coding:utf-8 -*-
from policy_chain import *
from bpf_map_def import * 
from utils import * 
from abc import abstractmethod
import uuid 
import threading
import queue
from functools import partial
import time
from socket import inet_aton
from multiprocessing import  Process, Queue, Value, cpu_count
from pexecute.process import ProcessLoom
import queue
import heapq
from math import ceil 

def setup_tc(): 
    TCEgressSelectorChain.config()
    TCEgressPolicyChain.config()
    selector_chain = TCEgressSelectorChain()
    if not selector_chain.init: 
        print("create new subflo")
        selector_chain.add("tcp", selector_op_type_t.SELECTOR_AND)
        selector_chain.submit()
    
    ac = TCEgressActionChain()
    ac.add("catch_mptcp_events")

    policy = TCEgressPolicyChain(selector_chain, ac)
    policy.set(0)

##################errors#####################
class eMPTCPTcpflowError(Exception):
    def __init__(self, error, tcpflow):
        super().__init__(self) #初始化父类
        self.errorinfo= error
        self.tcpflow = tcpflow

    def __str__(self):
        return self.errorinfo

class eMPTCPTcpflowAddError(eMPTCPTcpflowError):
    def __init__(self, tcpflow):
        super().__init__("tcp flow exists!", tcpflow)

##################errors#####################

class SubflowInfo: 
    xdp_selector_chain = None
    @classmethod
    def setup(cls): 
        XDPSelectorChain.config()
        XDPPolicyChain.config()
        cls.xdp_selector_chain = XDPSelectorChain()
        if not cls.xdp_selector_chain.init : 
            cls.xdp_selector_chain.add("tcp4", selector_op_type_t.SELECTOR_OR)
            cls.xdp_selector_chain.submit()
    
    @classmethod
    def take_action(cls, action, flow):
        assert(isinstance(action, eMPTCPConnection.Action) and "not action")
        recv_win = action.recv_win_ingress
        if recv_win == None: 
            return
        ac = XDPActionChain()
        ac.add("set_recv_win", recv_win = recv_win)
        policy_chain = XDPPolicyChain(cls.xdp_selector_chain, ac)
        policy_chain.set(0, tcp4 = flow)
      
    @classmethod
    def delete_action(cls, flow):
        policy_chain = XDPPolicyChain(cls.xdp_selector_chain)
        policy_chain.delete(0, tcp4 = flow)

    def __init__(self,flow, *, recv_win = None,**kw):
        assert(len(flow) == 4)
        self.action = eMPTCPConnection.Action()
        self.action.recv_win_ingress = recv_win
        self.flow = flow 

class eMPTCPConnection:
    class Action: 
        def __init__(self, recv_win_ingress = None):
            #decisiton attributes 
            self.recv_win_ingress = recv_win_ingress
            pass

    #tcp4tuple (local_port, remote_port, local_addr, remote_addr)


    def __init__(self, *, local_token, remote_token):
        self.id = uuid.uuid4()
        self.local_token = local_token 
        self.remote_token = remote_token 
        self.subflows = {}  #key tcp 4 元组， value : eMPTCPSubflow

    def infos(self):
        return self.subflows.values()

    def flows(self):
        return self.subflows.keys()

    def items(self):
        return self.subflows.items()

    def  __getitem__(self, key):
        return self.subflows[key]

    def add(self, tcpflow, **kw):
        if tcpflow in self.subflows: 
            raise eMPTCPTcpflowAddError(tcpflow)
        s =  SubflowInfo(tcpflow, **kw)
        self.subflows[tcpflow] = s
        return s

    def pop(self, tcpflow):
        SubflowInfo.delete_action(tcpflow) 
        return self.subflows.pop(tcpflow, None)

    def empty(self):
        return len(self.subflows) == 0

    def length(self):
        return len(self.subflows) 

    def take_action(self):
        for subflow in self.subflows.values():
            try:
                subflow.take_action()
            except Exception as e: 
                print(e)

## Policy
class SchedulerPolixy: 
    def __init__(self):
        pass 

    @abstractmethod
    def make(self, emptcp_connection):
        '''
            @param  
                emptcp_connection: eMPTCPConnection object 
                set decisiton attributes in emptcp_connection 
            return: 
                return next intervel and subflows needs to be update [subflows]
                interval, remote_token, [(flow, action), (flow, action)]
        '''
        pass 

class TestPolicy(SchedulerPolixy): 
    def __init__(self):
        super().__init__()
        pass 

    def make(self, emptcp_connection):
        assert(isinstance(emptcp_connection, eMPTCPConnection))
        actions = []
        for info in emptcp_connection.infos():
            if info.action.recv_win_ingress == None:
                actions.append((info.flow, eMPTCPConnection.Action(65535)))
        return 50, emptcp_connection.remote_token, actions

def print_tcp4_flow(flow):
    print("local_ip %s"%int2ip(int.from_bytes(val_2_bytes(flow.local_addr, 4), byteorder = "big", signed = False)))
    print("local_port %s"%int.from_bytes(val_2_bytes(flow.local_port, 2), byteorder = "big", signed = False))
    print("remote_ip %s"%int2ip(int.from_bytes(val_2_bytes(flow.remote_addr, 4), byteorder = "big", signed = False)))
    print("remote_port %s"%int.from_bytes(val_2_bytes(flow.remote_port, 2), byteorder = "big", signed = False))

def eMPTCP_event_process_func(q, running):
        def store_eMPTCP_events(queue, ctx, cpu,  data, size):
            if size < ct.sizeof(eMPTCP_event_header_t):
                return 
            e = ct.cast(data, ct.POINTER(eMPTCP_event_header_t)).contents
            event = e.event 
            if event == 1:
                queue.put(ct.cast(data, ct.POINTER(mp_capable_event_t)).contents)
            elif event == 2:
                queue.put(ct.cast(data, ct.POINTER(mp_join_event_t)).contents)
            elif event == 3:
                queue.put(ct.cast(data, ct.POINTER(fin_event_t)).contents)
            else:
                raise RuntimeError("unkonwn event :%d"%event)
        eMPTCP_events_fd = bpf_obj_get(TC_EGRESS_EMPTCP_EVENTS_PATH)
        with PerfBuffer(eMPTCP_events_fd, partial(store_eMPTCP_events, q)) as pb:
            while running.value:
                try:
                    pb.poll(timeout_ms = 10)
                except KeyboardInterrupt:
                    break

class eMPTCPScheduler:
    def __init__(self, policy, *, init_interval = 0 , parallel_ths = 100, parallel_level = cpu_count()):
        assert(isinstance(policy, SchedulerPolixy))
        self.policy = policy 
        self.eMPTCP_events_q = Queue()
        self.init_interval = init_interval
        self.remote_token_mpc_dict = {}
        self.local_token_mpc_dict = {}
        self.tcpflows = {}   #(MPTCP connection, MPTCP subflow)
        self.running = Value('b', False)  
        self.parallel_level = parallel_level
        self.parallel_ths = parallel_ths
        self.loom = ProcessLoom(max_runner_cap=parallel_level)
        self.scheduler_heapq = []     #(token, time)

    def start(self):
        self.running.value = True
        self.eMPTCP_event_process = Process(target = eMPTCP_event_process_func, args = [self.eMPTCP_events_q, self.running])
        self.eMPTCP_event_process.start()
        self._run()

    def _run(self):
        #consumer
        while True :
            now = round(time.time()*1000)
            try:
                #schedule one connection 
                e = self.eMPTCP_events_q.get(True, timeout = 0.01)
                try:
                    event = e.header.event 
                    if event == 1:
                        self._process_mpc_event(e, now)
                    elif event == 2:
                        self._process_mpj_event(e, now)
                    elif event == 3:
                        self._process_fin_event(e)
                    else:
                        raise RuntimeError("unkonwn event :%d"%event)
                except Exception as e: 
                    print(e)
                try:
                    connections = self._get_available_connections(now)
                    self._schedule(connections)
                except Exception as e:
                    print(e)
            except queue.Empty:
                pass 
            except KeyboardInterrupt:
                self.running.value = False 
                while not self.eMPTCP_events_q.empty():
                    _ = self.eMPTCP_events_q.get(True, timeout = 0.01)
                self.eMPTCP_event_process.join()
                exit() 
                
    def _get_available_connections(self, now):
        connections = []
        rt_set = set()
        while True and not len(self.scheduler_heapq) == 0: 
            currt = self.scheduler_heapq[0][0]
            if now >= currt:
                c = heapq.heappop(self.scheduler_heapq)[1]
                if c.remote_token not in rt_set:
                    connections.append(c)
                    rt_set.add(c.remote_token)
            else:
                break 
        return connections

    def _get_policies(self, connections):
        #use process loom 
        def batch_func(cons):
            l1 = []
            subl = []
            for c in cons:
                try:
                    intv, rt, actions = self.policy.make(c)
                    l1.append((intv, rt))
                    subl.extend(actions)
                except Exception as e:
                    print(e) 
            return l1, subl 
        
        if (len(connections) < self.parallel_ths):
            return batch_func(connections)
            
        batch_size = ceil(len(connections) / self.parallel_level)
        for b in range(self.parallel_level):
            begin = b*batch_size
            if (begin >= len(connections)) :
                break
            end = (b+1)*batch_size
            if end < len(connections) : 
                self.loom.add_function(batch_func, [connections[begin:end]])
            else:
                self.loom.add_function(batch_func, [connections[begin:]])
        outputs = self.loom.execute()
        next_l = []
        actions = []
        for output in outputs.values():
            if not output["got_error"]:
                next_l.extend(output["output"][0])
                actions.extend(output["output"][1])
        return next_l, actions
    
    def _take_policies(self, actions):
        def batch_func(acs):
            for f, a in acs:
                try:
                    SubflowInfo.take_action(a, f)
                except Exception as e:
                    print(e)
        if (len(actions) < self.parallel_ths):
            batch_func(actions)
            return  

        batch_size = ceil(len(actions) / self.parallel_level)
        for b in range(self.parallel_level):
            begin = b*batch_size
            if (begin > len(actions)) :
                break
            end = (b+1)*batch_size
            if end < len(actions) : 
                self.loom.add_function(batch_func, [ actions[begin:end] ])
            else:
                self.loom.add_function(batch_func, [ actions[begin:] ])
        self.loom.execute()

    def _schedule(self, connections):
        if len(connections) == 0:
            return
        try:
            next_l, actions = self._get_policies(connections)
            self._take_policies(actions)
            now = round(time.time()*1000)
            #re add to schedule_heapq
            bias = 0
            for l in next_l : 
                if l[1] not in self.remote_token_mpc_dict:
                    continue 
                heapq.heappush(self.scheduler_heapq, (l[0]+now+bias, self.remote_token_mpc_dict[l[1]]))
                bias+=1

            for flow, action in actions: 
                if flow in  self.tcpflows:
                    self.tcpflows[flow][1].action = action 

        except Exception as e: 
            print(e)

    def _process_mpc_event(self, mpce, t):
        tcpf = self._get_tcpflow(mpce.flow)
        if not self._check_black_list(tcpf):
            return 
        rk = mpce.remote_key
        rt_b =  calc_sha1_token(val_2_bytes(rk, 8))
        rt = bytes_2_val(rt_b)
        lk = mpce.local_key
        lt_b =  calc_sha1_token(val_2_bytes(lk, 8))
        lt = bytes_2_val(lt_b)
        #create new mptcp connection 
        if rt in self.remote_token_mpc_dict: 
            raise RuntimeError("mptcp rt cal exisits!, %d"%rt) 
        if lt in self.local_token_mpc_dict: 
            raise RuntimeError("mptcp lt cal exisits!, %d"%lt) 
        if tcpf in self.tcpflows:
            print_tcp4_flow(mpce.flow)
            raise RuntimeError("tcp flow exists!")
        c = eMPTCPConnection(local_token = lt, remote_token = rt)
        s = c.add(tcpf)
        self.remote_token_mpc_dict[rt] = c 
        self.local_token_mpc_dict[lt] = c 
        self.tcpflows[tcpf] = (c, s)
        heapq.heappush(self.scheduler_heapq, (t + self.init_interval, c))

    def _process_mpj_event(self, mpje, t):
        tcpf = self._get_tcpflow(mpje.flow)
        if not self._check_black_list(tcpf):
            return 
        #local->remote 
        rt = mpje.token 
        if tcpf in self.tcpflows:
            print_tcp4_flow(mpje.flow)
            raise RuntimeError("tcp flow exists!", tcpf)
        c = self.remote_token_mpc_dict[rt]
        s = c.add(tcpf)
        self.tcpflows[tcpf] = (c, s)
        heapq.heappush(self.scheduler_heapq, (t + self.init_interval, c))

    def _process_fin_event(self, fine):
        tcpf = self._get_tcpflow(fine.flow) 
        c,_ = self.tcpflows.get(tcpf, (None, None))
        if c == None: 
            return 
        c.pop(tcpf)
        if c.empty():
            rt = c.remote_token
            lt = c.local_token
            self.remote_token_mpc_dict.pop(rt)
            self.local_token_mpc_dict.pop(lt)
  
    def _get_tcpflow(self, tcp4):
        #tcp4tuple (local_port, remote_port, local_addr, remote_addr)
        flow = (tcp4.local_port, tcp4.remote_port, tcp4.local_addr, tcp4.remote_addr)
        return flow 
    
    def _check_black_list(self, flow):
        remote_addr = flow[3]
        local_addr = flow[2]
        
        local_list = [bytes_2_val(inet_aton("172.16.12.128")),bytes_2_val(inet_aton("172.16.12.129")), bytes_2_val(inet_aton("172.16.12.130"))]
        remote_list = [ bytes_2_val(inet_aton("172.16.12.131")),bytes_2_val(inet_aton("172.16.12.132")), bytes_2_val(inet_aton("172.16.12.133"))]
        #print("local: %s"int2ip(int.from_bytes(val_2_bytes(flow.local_addr, 4), byteorder = "big", signed = False)))
        if local_addr not in local_list:
            return False 
        if remote_addr not in remote_list:
            return False 
        return True

if __name__ == '__main__':
    setup_tc()
    SubflowInfo.setup()
    s = eMPTCPScheduler(TestPolicy())
    s.start()