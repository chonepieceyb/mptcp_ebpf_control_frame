#-*- coding:utf-8 -*-
from re import U
from bcc import BPF
import argparse
import os

from common import *
from bpf_loader import *
from utils import *
from libbpf import *
from bpf_map_def import *
from socket import if_nametoindex
from action_tool import FlowIngressAction

#测试用函数
def test_set_action():
    FlowIngressAction.config()
    '''
        flow_1 = FlowIngressAction(local_addr = "172.16.12.128", peer_addr = "172.16.12.132")
        flow_1.add("set_flow_prio", backup = 1, addr_id = None)
        flow_1.submit()

        flow_2 = FlowIngressAction(local_addr = "172.16.12.128", peer_addr = "172.16.12.133")
        flow_2.add("set_flow_prio", backup = 1, addr_id = None)
        flow_2.submit()

        flow_3 = FlowIngressAction(local_addr = "172.16.12.129", peer_addr = "172.16.12.131")
        flow_3.add("set_flow_prio", backup = 1, addr_id = None)
        flow_3.submit()

        flow_4 = FlowIngressAction(local_addr = "172.16.12.129", peer_addr = "172.16.12.133")
        flow_4.add("set_flow_prio", backup = 1, addr_id = None)
        flow_4.submit()

        flow_5 = FlowIngressAction(local_addr = "172.16.12.130", peer_addr = "172.16.12.131")
        flow_5.add("set_flow_prio", backup = 1, addr_id = None)
        flow_5.submit()

        flow_6 = FlowIngressAction(local_addr = "172.16.12.130", peer_addr = "172.16.12.132")
        flow_6.add("set_flow_prio", backup = 1, addr_id = None)
        flow_6.submit()
    '''
    '''
        flow_1 = FlowIngressAction(local_addr = "172.16.12.129", peer_addr = "172.16.12.132")
        flow_1.add("set_flow_prio", backup = 1, addr_id = 5)
        flow_1.submit()
    '''
    flow_2 = FlowIngressAction(local_addr = "172.16.12.128", peer_addr = "172.16.12.132")
    flow_2.add("set_flow_prio", backup = 1, addr_id = 5)
    flow_2.submit()
#为了方便暂时先使用bcc来加载，之后为了统一，考虑修改成使用 libbpf进行加载
class XdpLoader: 
    def __init__(self, interfaces, xdp_main, tail_call_list, loader): 
        if loader == BPFBCCLoader:
            self.path_key = "src_path"
        elif loader == BPFObjectLoader:
            self.path_key = "obj_path"
        else:
            raise RuntimeError("invalid loader")
        self.loader = loader 
        self.interfaces = interfaces
        self.xdp_main = xdp_main
        self.tail_call_list = tail_call_list 
        assert(len(self.interfaces) > 0)

    def attach(self): 
        with load(XDP_MAIN, self.loader, unpin_only_fail=True) as xdp_main:
            prog_array_fd = xdp_main.get_map_fd(XDP_ACTIONS)
            with TailCallLoader(prog_array_fd, XDP_TAIL_CALL_LIST, self.loader, clear_only_fail=True) as tl:
                for interface in self.interfaces: 
                    print("atttach xdp to %s"%interface)
                    #BPF.attach_xdp(interface, xdp_main.get_func("xdp_main"), flags=BPF.XDP_FLAGS_UPDATE_IF_NOEXIST)
                    bpf_xdp_attach(if_nametoindex(interface), xdp_main.get_prog_fd("xdp_main"), XDP_FLAGS.XDP_FLAGS_UPDATE_IF_NOEXIST, ct.c_void_p(None))
        test_set_action()

    def detach(self): 
        for interface in self.interfaces:
            print("move xdp of %s"%interface)
            BPF.remove_xdp(interface)
        
        unpin_obj(self.xdp_main)
        for obj in self.tail_call_list:
            unpin_obj(obj)

#使用 clsact disc 
#https://arthurchiao.art/blog/understanding-tc-da-mode-zh/#1-%E8%83%8C%E6%99%AF%E7%9F%A5%E8%AF%86linux-%E6%B5%81%E9%87%8F%E6%8E%A7%E5%88%B6tc%E5%AD%90%E7%B3%BB%E7%BB%9F
class TCLoader:
    add_qdisc_cmd = "sudo tc qdisc add dev %s clsact"
    add_tc_filter_cmd = "sudo tc filter add dev %s %s bpf %s obj %s"
    del_qdisc_cmd = "tc qdisc del dev %s clsact"

    def __init__(self, interfaces): 
        '''
        @param: 
            interfaces: interfaces to be attach or detach 
        '''

        self.interfaces = interfaces
        assert(len(self.interfaces) > 0)
    
    #可能不是很完善先这样
    def attach(self, targets) : 
        assert(isinstance(targets, list))
        assert(len(targets) > 0)    
        
        for interface in self.interfaces: 
            print("add clsact qdisc to %s"%interface)
            os.system(TCLoader.add_qdisc_cmd%interface)
    
            for target in targets:
                cmd = self._assemble_attach_cmd(target, interface)
                print(cmd)
                os.system(cmd)
        

    def detach(self) : 
        for interface in self.interfaces:
            print("del qdisc clsact of %s"%interface)
            os.system(TCLoader.del_qdisc_cmd%interface)

    def _assemble_attach_cmd(self, target, interface):
        obj = target["obj"]
        if "da_flag" in  target.keys() and target["da_flag"] == True:
            da_flag = "da"
        else:
            da_flag = ""
        direction = target["direction"]
        assert(direction in ["ingress", "egress"])
        return TCLoader.add_tc_filter_cmd%(interface, direction, da_flag, obj)

#mptcp ebpf control fram prog loader 
class ProgLoader:
    def __init__(self, arg_list): 
        parser = argparse.ArgumentParser(description="mptcp ebpf control frame prog loader")
        mode_group = parser.add_mutually_exclusive_group(required=True)
        mode_group.add_argument("-a", action="store_true", help="attach xdp&tc program")
        mode_group.add_argument("-d", action="store_true", help="remove xdp&tc program")
        parser.add_argument("--all", action="store_true", help="attach/detach xdp&tc program to all interfaces")
        parser.add_argument(metavar="interface", dest="interfaces", nargs="*", help="interface specifier")
        self.args = parser.parse_args(args = arg_list)
      
        if self.args.all:
            dump_all_if_config()
        elif len(self.args.interfaces) != 0: 
            dump_if_config(self.args.interfaces)

        interfaces =  read_if_config()
        if len(interfaces) == 0:
            print("without dev to attach or detach")
            exit()

        self.tc_loader = TCLoader(interfaces)
        self.xdp_loader = XdpLoader(interfaces, XDP_MAIN, XDP_TAIL_CALL_LIST, BPFBCCLoader)
        
    def run(self):
        if self.args.a:
            self._attach()
        elif self.args.d:
            self._detach()
        else:
            print("unkonwn mode")
            exit()

    def _attach(self):
        
        '''
        tc_ingress = {
            "obj" : os.path.join(BPF_TC_OBJS_PATH, CONFIG.tc.tc_ingress + ".c.o"),
            "da_flag" : False,
            "direction" : "ingress"
        }
        
        tc_egress = {
            "obj" : os.path.join(BPF_TC_OBJS_PATH, CONFIG.tc.tc_egress + ".c.o"),
            "da_flag" : False,
            "direction" : "egress"
        }
        '''
        #attach 
        #self.tc_loader.attach([tc_egress])
        self.xdp_loader.attach()
       
    def _detach(self):
        self.xdp_loader.detach()
        #self.tc_loader.detach()
        #clear config 
        with open(IF_CONF_PATH, 'w') as f: 
          f.truncate(0)

#testing 
if __name__ == '__main__' : 
    import sys
    tool = ProgLoader(sys.argv[1:])
    tool.run()
