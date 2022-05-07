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

#为了方便暂时先使用bcc来加载，之后为了统一，考虑修改成使用 libbpf进行加载
class XdpLoader: 
    def __init__(self, interfaces, loader): 
        if loader == BPFBCCLoader:
            self.path_key = "src_path"
        elif loader == BPFObjectLoader:
            self.path_key = "obj_path"
        else:
            raise RuntimeError("invalid loader")
        self.loader = loader 
        self.interfaces = interfaces
        assert(len(self.interfaces) > 0)

    def attach(self): 
        with load(XDP_SELECTOR_ENTRY, self.loader) as se, \
            load(XDP_ACTION_ENTRY, self.loader) as ae: 
            selectors_fd = se.get_map_fd(XDP_SELECTORS)
            actions_fd = ae.get_map_fd(XDP_ACTIONS)
            action_entry_idx = ct.c_int(ACTION_ENTRY_IDX)
            action_entry_fd = ct.c_int(ae.get_prog_fd("action_entry"))
            bpf_map_update_elem(actions_fd, ct.byref(action_entry_idx), ct.byref(action_entry_fd))
            with TailCallLoader(selectors_fd, XDP_SELECTORS_TAIL_CALL_LIST, self.loader) as stl,\
                TailCallLoader(actions_fd, XDP_ACTIONS_TAIL_CALL_LIST, self.loader) as atl:
                for interface in self.interfaces: 
                    print("atttach xdp to %s"%interface)
                    #BPF.attach_xdp(interface, xdp_main.get_func("xdp_main"), flags=BPF.XDP_FLAGS_UPDATE_IF_NOEXIST)
                    bpf_xdp_attach(if_nametoindex(interface), se.get_prog_fd("selector_entry"), XDP_FLAGS.XDP_FLAGS_UPDATE_IF_NOEXIST, ct.c_void_p(None))

    def detach(self): 
        for interface in self.interfaces:
            print("move xdp of %s"%interface)
            BPF.remove_xdp(interface)
        unpin_obj(XDP_SELECTOR_ENTRY)
        unpin_obj(XDP_ACTION_ENTRY)
        for obj in XDP_SELECTORS_TAIL_CALL_LIST:
            unpin_obj(obj)
        for obj in XDP_ACTIONS_TAIL_CALL_LIST:
            unpin_obj(obj)

class TCEgressProgLoader: 
    #load using libbpf 
    def __init__(self, interfaces, loader): 
        '''
        @param: 
            interfaces: interfaces to be attach or detach 
        '''
        self.interfaces = interfaces
        assert(len(self.interfaces) > 0)
        self.loader = loader

    def attach(self):
        self._create_hooks()
        with load(TC_EGRESS_SELECTOR_ENTRY, self.loader) as se, \
             load(TC_EGRESS_ACTION_ENTRY, self.loader) as ae: 
            selectors_fd = se.get_map_fd(TC_EGRESS_SELECTORS)
            actions_fd = ae.get_map_fd(TC_EGRESS_ACTIONS)
            action_entry_idx = ct.c_int(ACTION_ENTRY_IDX)
            action_entry_fd = ct.c_int(ae.get_prog_fd("action_entry"))
            bpf_map_update_elem(actions_fd, ct.byref(action_entry_idx), ct.byref(action_entry_fd))
            with TailCallLoader(selectors_fd, TC_E_SELECTORS_TAIL_CALL_LIST, self.loader) as stl,\
                TailCallLoader(actions_fd, TC_E_ACTIONS_TAIL_CALL_LIST, self.loader) as atl:
                for interface in self.interfaces:
                    print("atttach tc egress to %s"%interface)
                    ifindex = if_nametoindex(interface)
                    egress_hook = init_libbpf_opt(bpf_tc_hook, ifindex = ifindex, attach_point = BPF_TC_ATTACH_POINT.BPF_TC_EGRESS)
                    opts = init_libbpf_opt(bpf_tc_opts, prog_fd = se.get_prog_fd("selector_entry"))
                    bpf_tc_attach(egress_hook, opts)

    def detach(self):
        self._destroy_hooks()
        unpin_obj(TC_EGRESS_SELECTOR_ENTRY)
        unpin_obj(TC_EGRESS_ACTION_ENTRY)
        for obj in TC_E_SELECTORS_TAIL_CALL_LIST:
            unpin_obj(obj)
        for obj in TC_E_ACTIONS_TAIL_CALL_LIST:
            unpin_obj(obj)
    
    def _create_hooks(self):
        for interface in self.interfaces:
            ifindex = if_nametoindex(interface)
            hook = init_libbpf_opt(bpf_tc_hook, ifindex = ifindex, attach_point = BPF_TC_ATTACH_POINT.BPF_TC_INGRESS | BPF_TC_ATTACH_POINT.BPF_TC_EGRESS)
            bpf_tc_hook_create(hook)

    def _destroy_hooks(self):
        for interface in self.interfaces:
            try: 
                print("move tc egress: %s"%interface)
                ifindex = if_nametoindex(interface)
                hook = init_libbpf_opt(bpf_tc_hook, ifindex = ifindex, attach_point = BPF_TC_ATTACH_POINT.BPF_TC_INGRESS | BPF_TC_ATTACH_POINT.BPF_TC_EGRESS)
                bpf_tc_hook_destroy(hook)
            except Exception:
                pass

#mptcp ebpf control fram prog loader 
LOADER = BPFObjectLoader
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

        self.tc_egress_loader = TCEgressProgLoader(interfaces, LOADER)
        self.xdp_loader = XdpLoader(interfaces, LOADER)
        
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
        try:
            self.xdp_loader.attach()
            self.tc_egress_loader.attach()
        except Exception as e :
            print(e)
            self._detach()
       
    def _detach(self):
        self.xdp_loader.detach()
        self.tc_egress_loader.detach()
        #clear config 
        with open(IF_CONF_PATH, 'w') as f: 
          f.truncate(0)

#testing 
if __name__ == '__main__' : 
    import sys
    tool = ProgLoader(sys.argv[1:])
    tool.run()
