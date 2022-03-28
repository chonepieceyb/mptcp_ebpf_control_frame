#-*- coding:utf-8 -*-
from bcc import BPF
import argparse
import os

from common import *
from bpf_func_loader import BPFFuncLoader
from config import CONFIG
from utils import *
from libbpf import *

#为了方便暂时先使用bcc来加载，之后为了统一，考虑修改成使用 libbpf进行加载
class XdpLoader: 
    def __init__(self, interfaces): 
        self.interfaces = interfaces
        assert(len(self.interfaces) > 0)

    def attach(self, prog_path) : 
        xdp_main = BPFFuncLoader(prog_path, BPF.XDP, cflags = ["-I%s"%SRC_BPF_KERN_PATH])
        for interface in self.interfaces: 
            print("atttach xdp to %s"%interface)
            BPF.attach_xdp(dev=interface, fn = xdp_main.func, flags=BPF.XDP_FLAGS_UPDATE_IF_NOEXIST)

    def detach(self) : 
        for interface in self.interfaces:
            print("move xdp of %s"%interface)
            BPF.remove_xdp(interface)
        
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
        self._load_tailcall_funcs()
        
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

    def _load_tailcall_funcs(self):
        join_path = os.path.join(BPF_TC_BTF_OBJS_PATH, "tc_egress_join.c.o")
        mpc_path = os.path.join(BPF_TC_BTF_OBJS_PATH, "tc_egress_mpcapable.c.o")
        tail_path = os.path.join(BPF_TC_BTF_OBJS_PATH, "tc_egress_tailcall.c.o")

        #open
        join_obj = bpf_object__open(join_path)  
        mpc_obj = bpf_object__open(mpc_path)
        tail_obj = bpf_object__open(tail_path)
        
        tail_map = bpf_object__find_map_by_name(tail_obj, "tc_egress_tailcall")
        mpc_prog = bpf_object__find_program_by_name(mpc_obj, "tc_egress_mpcapable")
        mpj_prog = bpf_object__find_program_by_name(join_obj, "tc_egress_join")
        
        mp_connect = bpf_object__find_map_by_name(join_obj, "mptcp_connects")
        subflows = bpf_object__find_map_by_name(join_obj, "subflows")
        mp_capable_output = bpf_object__find_map_by_name(mpc_obj, "mp_capable_perf_output")
        
        if os.path.exists(MPTCP_OUTPUT_PATH) : 
            mptcp_output_fd = bpf_obj_get(MPTCP_OUTPUT_PATH)
            print("reuse mp output %d"%mptcp_output_fd)
            bpf_map__reuse_fd(mp_capable_output, mptcp_output_fd)

        if os.path.exists(SUBFLOWS_PATH) : 
            subflows_fd = bpf_obj_get(SUBFLOWS_PATH)
            print("reuse subflow %d"%subflows_fd)
            bpf_map__reuse_fd(subflows, subflows_fd)
        
        if os.path.exists(MPTCP_CONNECTS_PATH):
            mp_connects_fd = bpf_obj_get(MPTCP_CONNECTS_PATH)
            print("reuse mptcp connects %d"%mp_connects_fd)
            bpf_map__reuse_fd(mp_connect, mp_connects_fd)
        
        if os.path.exists(TC_EGRESS_TAILCALL_PATH):
            tail_call_fd = bpf_obj_get(TC_EGRESS_TAILCALL_PATH)
            print("reuse tail call %d"%tail_call_fd)
            bpf_map__reuse_fd(tail_map, tail_call_fd)

        #load 
        bpf_object__load(join_obj)
        bpf_object__load(mpc_obj)
        bpf_object__load(tail_obj)
        #pin and get fd 
        
        '''
        tail_prog = """
        BPF_TABLE_PINNED("prog", int, int, tc_egress_tailcall, 4, "/sys/fs/bpf/tc/globals/tc_egress_tailcall");
        """
        bpf = BPF(text = tail_prog)
        print(TC_EGRESS_TAILCALL_PATH)
        tail_map_fd = bpf_obj_get(TC_EGRESS_TAILCALL_PATH)
        '''

        tail_map_fd = pin_tc_egress_tailcall_obj(tail_map)
        mpc_fd = pin_tc_egress_mpcapable_obj(mpc_prog)
        mpj_fd = pin_tc_egress_join_obj(mpj_prog)

        pin_mptcp_connects_obj(mp_connect)
        pin_subflows_obj(subflows)
        pin_mptcp_output_obj(mp_capable_output)

        
        mpc_index = ct.c_int(0)
        mpj_index = ct.c_int(1)
        mpc_fd = ct.c_int(mpc_fd)
        mpj_fd = ct.c_int(mpj_fd)
        #set tail call 
        bpf_map_update_elem(tail_map_fd, ct.byref(mpc_index), ct.byref(mpc_fd))
        bpf_map_update_elem(tail_map_fd, ct.byref(mpj_index), ct.byref(mpj_fd))
        

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
        self.xdp_loader = XdpLoader(interfaces)
        
    def run(self):
        if self.args.a:
            self._attach()
        elif self.args.d:
            self._detach()
        else:
            print("unkonwn mode")
            exit()

    def _attach(self):
        xdp_main_path = os.path.join(XDP_PROG_PATH, CONFIG.xdp.xdp_main + ".c")
        
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
    
        #attach 
        self.tc_loader.attach([tc_egress])
        self.xdp_loader.attach(xdp_main_path)
       
    def _detach(self):
        self.xdp_loader.detach()
        self.tc_loader.detach()
        self._clear_bpf_map()
        #clear config 
        with open(IF_CONF_PATH, 'w') as f: 
          f.truncate(0)

    def _clear_bpf_map(self):
        #暂时放这
        unpin(MPTCP_OUTPUT_PATH)
        unpin(MPTCP_CONNECTS_PATH)
        unpin(SUBFLOWS_PATH)
        unpin(TC_EGRESSS_JOIN_PATH)
        unpin(TC_EGRESS_TAILCALL_PATH)
        unpin(TC_EGRESSS_MPCAPABLE_PATH)
        os.system("sudo rm -rf /sys/fs/bpf/xdp/globals/*")
#testing 
if __name__ == '__main__' : 
    import sys
    tool = ProgLoader(sys.argv[1:])
    tool.run()
