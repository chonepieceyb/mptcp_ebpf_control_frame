#-*- coding:utf-8 -*-
import os
from bpf_func_loader import BPFFuncLoader
import ctypes as ct 
from libbpf import *
from config import CONFIG
import argparse
from bpf_func_loader import BPFFuncLoader
from bcc import BPF

class XDPActions: 
    xdp_actions_path = os.path.join(CONFIG.bpf_virtual_fs_path, CONFIG.xdp_actions.name)
    xdp_actions_fd = None

    @classmethod
    def init(cls):
        if cls.xdp_actions_fd != None: 
            return 
        if os.path.exists(cls.xdp_actions_path) :
            cls.xdp_actions_fd = bpf_obj_get(cls.xdp_actions_path)
        else: 
            cls.xdp_actions_fd  = bpf_create_map(BPF_MAP_TYPE.BPF_MAP_TYPE_PROG_ARRAY, 4, 4, CONFIG.xdp_actions.max_entries)
            bpf_obj_pin(cls.xdp_actions_fd, cls.xdp_actions_path)  #pin to bpf virtual fs 

    @classmethod
    def set_action_by_fd(cls, fd, action):
        '''
        @param:
            fd: func fd 
            action: bpf prog array index
        '''
        fd_p = ct.pointer(ct.c_int(fd))
        action_p = ct.pointer(ct.c_int(action))
        bpf_map_update_elem(cls.xdp_actions_fd, action_p, fd_p)
    
    @classmethod
    def set_action_by_name(cls, func, action):
        '''
        @param: 
            func : func name under bpf virtual filesystem
            action: bpf prog array index
        '''
        path = os.path.join(CONFIG.bpf_virtual_fs_path, func)
        if not os.path.exists(path) :
            raise RuntimeError("%s not exists in bpf virtual filesystem"%func)
        func_fd = bpf_obj_get(path)
        cls.set_action_by_fd(func_fd, action)

    @classmethod
    def delete_action(cls, action):
        '''
        @param:
            action: bpf prog array index 
        '''
        action_p = ct.pointer(ct.c_int(action))
        bpf_map_delete_elem(cls.xdp_actions_fd, action_p)

#init 
try :
    XDPActions.init()
except LinuxError as e:
    print(e)

class XDPActionsTool:
    def __init__(self, args_list):
        parser = argparse.ArgumentParser(description="XDP ActionsTool")

        #mode set or delete action 
        mode_group = parser.add_mutually_exclusive_group(required=True)
        mode_group.add_argument("-s", "--set" ,action="store_true", help="set xdp action")
        mode_group.add_argument("-r", "--remove", action="store_true", help="remove xdp action")

        set_target_group = parser.add_mutually_exclusive_group()
        set_target_group.add_argument("-f", "--file", action="store_true", help= "compile bpf func from bpf file, pinned to bpf virtual filesystem and set it to xdp_actions")
        set_target_group.add_argument("-n", "--name", action = "store_true", help = "set xdp actions by funcname(already pinned to bpf vfs")
        set_target_group.add_argument("-F", "--fd", action = "store_true", help = "set xdp actions by fd(already pinned to bpf vfs")

        parser.add_argument("-t", "--target", type = str, help = "target to be set, depend on options [-fnF]")
        
        #compile from file can set cflags 
        parser.add_argument("-c", "--cflags", default = [], metavar="\"-I xxx\"", nargs = '*', help = 'bcc cflags')
        
        #position arguments
        parser.add_argument("action", type = int, help = "xdp action id")
        self.args = parser.parse_args(args = args_list)

    def run(self):
        if self.args.set:
            self._set_action()
        elif self.args.remove:
            self._remove_action()
        else:
            raise RuntimeError("XDP Actions Tool invalid mode")

    def _set_action(self):
        if self.args.target == None: 
            raise RuntimeError("XDPActionTool fail to set action without target")
        
        action = self.args.action
        if self.args.file:
            fd = self._load_func()
            XDPActions.set_action_by_fd(fd, action)
        elif self.args.name:
            XDPActions.set_action_by_name(self.args.target, action)
        elif self.args.fd: 
            fd = int(self.args.target)
            XDPActions.set_action_by_fd(fd, action)
        else:
            raise RuntimeError("XDP Actions Tool unkonwen target")

    def _load_func(self):
        self.func = BPFFuncLoader(os.path.abspath(self.args.target), BPF.XDP, cflags = self.args.cflags)
        self.func.pin()
        return self.func.fd

    def _remove_action(self):
        XDPActions.delete_action(self.args.action)

if __name__ == '__main__':
    import sys 
    tool = XDPActionsTool(sys.argv[1:])
    tool.run()
