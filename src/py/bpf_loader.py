#-*- coding:utf-8 -*-
from bcc import BPF
import os
from abc import abstractmethod

from libbpf import *
from utils import unpin

class BPFLoaderBase: 
    class BPFFd:
        def __init__(self, fd, pin_path = None):
            self.fd = fd
            self.pin_path = pin_path

    def __init__(self, progs, pin_maps, loaded):
        self.prog_fds = {}
        self.map_fds = {}
        self.loaded = loaded
        if loaded : 
            #fd and pin_path set by subcalss
            return

        #get fd and pin path from pin_path 
        for name, prog in progs.items(): 
            if not "pin_path" in prog: 
                continue 
            pin_path = prog["pin_path"]
            fd = bpf_obj_get(pin_path)
            self.prog_fds[name] = BPFLoaderBase.BPFFd(fd, pin_path)
        
        for name, pin_path in pin_maps.items(): 
            fd = bpf_obj_get(pin_path)
            self.map_fds[name] = BPFLoaderBase.BPFFd(fd, pin_path)
                
    def unpin(self):
        for _, map_fd in self.map_fds.items():
            if map_fd.pin_path != None:
                unpin(map_fd.pin_path, None)
        
        for _, prog_fd in self.prog_fds.items():
            if prog_fd.pin_path != None:
                unpin(prog_fd.pin_path, None)


    def get_map_fd(self, name):
        if name in self.map_fds:
            return self.map_fds[name].fd
        
        if self.loaded:
            fd, pin_path = self._get_map_fd_load(name)
            self.map_fds[name] = BPFLoaderBase.BPFFd(fd, pin_path)
            return fd
       
        raise RuntimeError('BPFLoader fail to get map(not exists or unload without pinned): %s'%name)
    
    def get_prog_fd(self, name):
        if name in self.prog_fds:
            return self.prog_fds[name].fd
        
        if self.loaded:
            fd, pin_path = self._get_prog_fd_load(name)
            self.prog_fds[name] = BPFLoaderBase.BPFFd(fd, pin_path)
            return fd 
        
        raise RuntimeError('BPFLoader fail to get prog(not exists): %s'%name)

    @abstractmethod
    def _get_map_fd_load(self, name):
        #implement by subclass
        pass

    @abstractmethod
    def _get_prog_fd_load(self, name):
        #implement by subclass
        pass


class BPFObjectLoader(BPFLoaderBase):
    def __init__(self, path, *, progs, pin_maps, loaded):
        super().__init__(progs, pin_maps, loaded)
        '''
        load bpf object using libbpf 
        @param:
            path: path to bpf object 
            progs: dict progs (all progs)
                prog_name : {
                    "prog_type" : BPF_PROG_TYPE
                    "pin_path" : "if pin prog"
                }
            pin_maps: maps to be pinned, key : map name , value : pin_paths
        '''

        if loaded:
            self.progs = progs
            self.pin_maps = pin_maps
            self.bpf_obj = bpf_object__open(os.path.abspath(path))
            self.__load()

    def _get_map_fd_load(self, name):
        if name in self.pin_maps:
            return bpf_obj_get(self.pin_maps[name]), self.pin_maps[name]
        
        bpf_map = bpf_object__find_map_by_name(self.bpf_obj, name)
        return bpf_map__fd(bpf_map), None
    
    def _get_prog_fd_load(self, name):
        if not name in self.progs:
            raise RuntimeError("prog %s doesn't exists"%name)
        prog = self.progs[name]
        
        if "pin_path" in prog:
            return bpf_obj_get(prog["pin_path"]), prog["pin_path"]
        
        prog_obj = bpf_object__find_program_by_name(self.bpf_obj, name)
        return bpf_program__fd(prog_obj), None

    def __load(self):
        self.__set_pin_maps()
        self.__set_progs_type()
        bpf_object__load(self.bpf_obj)   #load bpf object
        self.__pin_progs()               #pin progs
        pass

    def __set_pin_maps(self):
        for name, pin_path in self.pin_maps.items():
            bpf_map = bpf_object__find_map_by_name(self.bpf_obj, name)
            bpf_map__set_pin_path(bpf_map, pin_path)

    def __set_progs_type(self):
        for name, prog in self.progs.items(): 
            if not "prog_type" in prog:
                raise RuntimeError("prog :%s without prog type"%name)
            prog_obj = bpf_object__find_program_by_name(self.bpf_obj, name)
            bpf_program__set_type(prog_obj, prog["prog_type"])

    def __pin_progs(self):
        for name, prog in self.progs.items(): 
            if not "pin_path" in prog :
                continue 
            pin_path = prog["pin_path"]
            if os.path.exists(pin_path):
                raise RuntimeError("failed to pin program %s, already exists"%pin_path)
            prog_obj = bpf_object__find_program_by_name(self.bpf_obj, name)
            bpf_program__pin(prog_obj, pin_path)

class BPFBCCLoader(BPFLoaderBase): 
    def __init__(self, path, *, progs, pin_maps, loaded, cflags = []):
        '''
        compile bpf src file , load func and pin the func
        @param:
            path: path to bpf object 
            progs: dict progs (all progs)
                prog_name : {
                    "prog_type" : BPF_PROG_TYPE
                    "pin_path" : "if pin prog"
                }
            pin_maps: maps to be pinned, key : map name , value : pin_paths
        '''
        super().__init__(progs, pin_maps, loaded) 
        
        if loaded:
            self.progs = progs
            self.pin_maps = pin_maps
            self.funcs = {}
            self.bpf = BPF(src_file = path, cflags = cflags)
            self.__load_funcs_and_pin()

    def get_table(self, name):
        if self.loaded:
            return self.bpf.get_table(name)
        else:
            raise RuntimeError("failed to get table with loaded = False")

    def get_func(self, name):
        if self.loaded:
            return self.funcs[name]
        else:
            raise RuntimeError("failed to get func with loaded = False")
    

    def _get_map_fd_load(self, name):
        if name in self.pin_maps:
            return bpf_obj_get(self.pin_maps[name]), self.pin_maps[name]
    
        return self.bpf.get_table(name).map_fd, None
    
    def _get_prog_fd_load(self, name):
        if not name in self.progs:
            raise RuntimeError("prog %s doesn't exists"%name)
        
        prog = self.progs[name]
        if "pin_path" in prog:
            return bpf_obj_get(prog["pin_path"]), prog["pin_path"]
        
        return self.funcs[name].fd, None
        
    def __load_funcs_and_pin(self):
        for name, prog in self.progs.items():
            if not "prog_type" in prog:
                raise RuntimeError("prog :%s without prog type"%name)
            func = self.bpf.load_func(name, prog["prog_type"])

            #pin func
            if "pin_path" in prog:
                bpf_obj_pin(func.fd, prog["pin_path"])
            
            self.funcs[name] = func
   
# test program 
if __name__ == '__main__': 
    from common import *
    file = '/home/chonepieceyb/CODING/WorkSpace/mptcp_ebpf_control_frame/src/bpf_kern/xdp/xdp_main.c'
    obj = "/home/chonepieceyb/CODING/WorkSpace/mptcp_ebpf_control_frame/install/bpf_kern_objs/xdp/xdp_main.c.o"
    pin_maps = {
        "xdp_actions" : "/sys/fs/bpf/mptcp_ebpf_control_frame/xdp_actions",
        "subflow_action_ingress": "/sys/fs/bpf/mptcp_ebpf_control_frame/subflow_action_ingress"
    }

    progs = {
        "xdp_main" : {
            "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
        }
    }

    #load by BCC
    obj_loader = BPFObjectLoader(obj, progs = progs, pin_maps = pin_maps)
    print("actions fd%s"%obj_loader.get_map_fd("xdp_actions"))
    print("subflows fd%s"%obj_loader.get_map_fd("subflow_action_ingress"))
    print("xdp mian fd%s"%obj_loader.get_prog_fd("xdp_main"))

    bcc_loader = BPFBCCLoader(file, progs = progs, pin_maps = pin_maps, cflags = ["-I%s"%SRC_BPF_KERN_PATH, "-g", "-O2"])
    print("actions fd%s"%bcc_loader.get_map_fd("xdp_actions"))
    print("subflows fd%s"%bcc_loader.get_map_fd("subflow_action_ingress"))
    
    

    


    
    
    


    