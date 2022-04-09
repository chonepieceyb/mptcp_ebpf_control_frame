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

class TailCallLoader: 
    def __init__(self, prog_array_fd, tail_call_list, loader = BPFBCCLoader):
        '''
            tail_call_dict : [
                {
                    "src_path" : {

                    },
                    "obj_path" : {
                        
                    },
                    "progs" : {

                    },
                    "pin_maps": {

                    },
                    "kw" : {
                        
                    }, 
                    "tail_call_map" : {
                        "name" : index,
                    }
                }
            ]
        '''
        if loader == BPFBCCLoader:
            path_key = "src_path"
        elif loader == BPFObjectLoader:
            path_key = "obj_path"
        else:
            raise RuntimeError("invalid loader")
        
        self.prog_array_fd = prog_array_fd
        self.bpf_loader = []
        self.tail_call_map = {}  # key : tail_call_index, value : fd 
        try: 
            for item in tail_call_list:
                self.bpf_loader.append(loader(item[path_key], progs = item["progs"], pin_maps = item["pin_maps"], **item["kw"]))
            self._set_tail_call_map()
            self._load()
        except Exception as e:
            self.clear()
            raise e 

    def unpin_maps(self):
        for loader in self.bpf_loader:
            loader.unpin_maps()

    def unpin_progs(self):
        #delete prog fd in prog_array_fd
        for loader in self.bpf_loader:
            loader.unpin_progs()
    
    def unpin(self):
        self.unpin_maps()
        self.unpin_progs()

    def unload(self):
        for key, _ in self.tail_call_map.items():
            tail_call_index = ct.c_int(int(key))
            bpf_map_delete_elem(self.prog_array_fd, ct.byref(tail_call_index))

    def clear(self):
        self.unload()
        self.unpin()

    def _set_tail_call_map(self):
        for idx_str, val in XDP_TAILCALL_IDX_NAME_MAP.items():
            list_idx = int(val["list_idx"])
            func_name = val["tail_call_name"]
            fd = self.bpf_loader[list_idx].get_prog_fd(func_name)
            self.tail_call_map[idx_str] = fd

    def _load(self):
        for key, fd in self.tail_call_map.items():
            tail_call_index = ct.c_int(int(key))
            fd_c = ct.c_int(fd)
            bpf_map_update_elem(self.prog_array_fd, ct.byref(tail_call_index), ct.byref(fd_c))        
                
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
        xdp_main = None 
        tailcall_loader = None
        try:
            xdp_main = self.loader(XDP_MAIN[self.path_key], progs = XDP_MAIN["progs"], pin_maps = XDP_MAIN["pin_maps"], **XDP_MAIN["kw"])
            xdp_actions_fd = xdp_main.get_map_fd(XDP_ACTIONS)
            tailcall_loader = TailCallLoader(xdp_actions_fd, XDP_TAIL_CALL_LIST, self.loader)

            #暂时只支持用bcc load
            for interface in self.interfaces: 
                print("atttach xdp to %s"%interface)
                #BPF.attach_xdp(interface, xdp_main.get_func("xdp_main"), flags=BPF.XDP_FLAGS_UPDATE_IF_NOEXIST)
                bpf_xdp_attach(if_nametoindex(interface), xdp_main.get_prog_fd("xdp_main"), XDP_FLAGS.XDP_FLAGS_UPDATE_IF_NOEXIST, ct.c_void_p(None))
        except Exception as e: 
            if xdp_main != None: 
                xdp_main.unpin()
            if tailcall_loader != None:
                tailcall_loader.clear()
            print(e)

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
