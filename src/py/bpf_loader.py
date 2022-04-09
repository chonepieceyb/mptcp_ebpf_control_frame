#-*- coding:utf-8 -*-
from sys import implementation
from bcc import BPF
import os
from abc import abstractmethod

from libbpf import *
from utils import unpin
from error import *
from enum import IntEnum, unique

def bpf_check_load(cls_func):
    def check_load(*args, **kw):
        if args[0].loaded == None or args[0].loaded == False :
            raise BPFLoadError("bpf loader init but unload")
        return cls_func(*args, **kw)
    return check_load

class BPFLoaderBase: 
    @unique 
    class PIN_MAP_FLAG(IntEnum):
        REUSE = 1,
        PIN  = 2,
        PIN_IF_NOT_EXIST = 3

    class BPFRunTimeInfo:
        def __init__(self, fd, pinned):
            self.fd = fd  #fd == -1 means not get fd now 
            self.pinned = pinned

    @classmethod
    def get_pin_map_flag(cls, map_info):
        flag = cls.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        if "flag" in map_info:
            flag = map_info["flag"]
        return flag 

    def __init__(self, *, progs, pin_maps, unpin_only_fail = True):
        self.runtime_progs = {}    
        self.runtime_maps = {}    
        self.progs = progs
        self.pin_maps = pin_maps 
        self.unpin_only_fail = unpin_only_fail

    def __enter__(self):
        self.load()
        return self

    def __exit__(self, type, value, trace):
        #fail 
        fail = False 
        if type != None or value != None or trace != None:
            fail = True
            print("type: ", type)
            print("value: \n", value)
            print("trace: \n", trace)
        
        #if fail unpin 
        #if not fail unpin only when self.unpin_only_fail set False
        if fail or self.unpin_only_fail == False:
            self.unpin()

    def load(self):
        self._load()
        self.loaded = True
    
    @bpf_check_load
    def get_map_fd(self, name):
        if name in self.runtime_maps and self.runtime_maps[name].fd >= 0:
            return self.runtime_maps[name].fd
        rt_info = self._get_map_runtime_info(name)
        self.runtime_maps[name] = rt_info
        return rt_info.fd
    
    @bpf_check_load
    def get_prog_fd(self, name):
        if name in self.runtime_progs and self.runtime_progs[name].fd >= 0:
            return self.runtime_progs[name].fd
        rt_info = self._get_prog_runtime_info(name)
        self.runtime_progs[name] = rt_info
        return rt_info.fd
    
    def unpin(self):
        self._unpin_maps()
        self._unpin_progs()

    @abstractmethod
    def _load(self):
        #impelete by subclass
        pass 
    
    def _unpin_maps(self):
        for name, rt_info in self.runtime_maps.items():
            if not rt_info.pinned:
                continue 
            try: 
                map_info = self.pin_maps[name]
                flag = BPFLoaderBase.get_pin_map_flag(map_info)
                assert(flag !=  BPFLoaderBase.PIN_MAP_FLAG.REUSE)
                print("unpin: %s"%map_info["pin_path"])
                unpin(map_info["pin_path"], None)
            except Exception as e:
                print(e)
    
    def _unpin_progs(self):
        for name , rt_info in self.runtime_progs.items():
            if not rt_info.pinned:
                continue
            try:
                prog_info = self.progs[name]
                print("unpin: %s"%prog_info["pin_path"])
                unpin(prog_info["pin_path"], None)
            except Exception as e:
                print(e)
    
    @abstractmethod
    def _get_map_runtime_info(self, name):
        #implement by subclass
        pass

    @abstractmethod
    def _get_prog_runtime_info(self, name):
        #implement by subclass
        pass 

class BPFPINLoader(BPFLoaderBase):
    def __init__(self, *, progs, pin_maps):
        super().__init__(progs=progs, pin_maps = pin_maps)
    
    def _load(self):
        for name, prog_info in self.progs.items(): 
            if not "pin_path" in prog_info: 
                continue 
            pin_path = prog_info["pin_path"]
            fd = bpf_obj_get(pin_path)
            self.runtime_progs[name] = BPFLoaderBase.BPFRunTimeInfo(fd, True)
            
        for name, map_info in self.pin_maps.items(): 
            fd = bpf_obj_get(map_info["pin_path"])
            self.runtime_maps[name] = BPFLoaderBase.BPFRunTimeInfo(fd, True)
    
    def __exit__(self, type, value, trace):
        pass

    def _get_map_runtime_info(self, name):
        raise BPFLoadError("BPFPINLoader only load pinned map")

    def _get_prog_runtime_info(self, name):
        raise BPFLoadError("BPFPINLoader only load pinned prog")
    
    def unpin(self):
        raise BPFLoadError("BPFPINLoader not support unpin")

class BPFObjectLoader(BPFLoaderBase):
    def __init__(self, path, *, progs, pin_maps, unpin_only_fail = True, **kw):
        super().__init__(progs = progs, pin_maps = pin_maps, unpin_only_fail = unpin_only_fail)
        '''
        load bpf object using libbpf 
        @param:
            path: path to bpf object 
            progs: dict progs (all progs)
                prog_name : {
                    "prog_type" : BPF_PROG_TYPE
                    "pin_path" : "if pin prog"
                }
            pin_maps : maps to be pinned, key : map name value : 
                {
                    "pin_path" : pin path 
                    "flag" : pin_flag
                        when create: 
                            1. REUSE (reuse maps map must has been pinned) 
                            2. PIN (pin maps, map must not have been pinned)
                            3. PIN_IF_NOT_EXIST(if maps have been pinned reuse it else pin it)
                            default PIN_IF_NOT_EXIST
                            (BCC only support PIN_IF_NOT_EXIST)
                        when unpin: 
                            PIN and PIN_IF_NOT_EXIST will delete pin_object 
                            PIN_IF_NOT_EXIST depends on if create the file
                            REUSE  won't
                } 
        '''
        self.path = path
    
    def _load(self):
        self.bpf_obj = bpf_object__open(os.path.abspath(self.path))
        self.__pin_maps()
        self.__set_progs_type()
        bpf_object__load(self.bpf_obj)   #load bpf object
        self.__pin_progs()               #pin progs

    def _get_map_runtime_info(self, name):
        if name in self.pin_maps:
            return BPFLoaderBase.BPFRunTimeInfo(bpf_obj_get(self.pin_maps[name]["pin_path"]), self.runtime_maps[name].pinned)
        bpf_map = bpf_object__find_map_by_name(self.bpf_obj, name)
        return BPFLoaderBase.BPFRunTimeInfo(bpf_map__fd(bpf_map), False)
    
    def _get_prog_runtime_info(self, name):
        if not name in self.progs:
            raise BPFLoadError("prog %s doesn't exists"%name)

        prog_info = self.progs[name]
        
        if "pin_path" in prog_info:
            return BPFLoaderBase.BPFRunTimeInfo(bpf_obj_get(prog_info["pin_path"]), self.runtime_progs[name].pinned)
        
        prog_obj = bpf_object__find_program_by_name(self.bpf_obj, name)
        return BPFLoaderBase.BPFRunTimeInfo(bpf_program__fd(prog_obj), False)

    def __pin_maps(self):
        for name, map_info in self.pin_maps.items():
            self.__pin_map(name, map_info)
    
    def __pin_map(self, name, map_info):
        pin_map_flag = BPFLoaderBase.get_pin_map_flag(map_info)
        bpf_map = bpf_object__find_map_by_name(self.bpf_obj, name)
        pin_path = map_info["pin_path"]
        need_pin = False 
        need_reuse = False 

        if pin_map_flag == BPFObjectLoader.PIN_MAP_FLAG.PIN:
            if os.path.exists(pin_path):
                raise BPFPinObjExist(pin_path)
            need_pin = True

        elif pin_map_flag ==  BPFObjectLoader.PIN_MAP_FLAG.REUSE:
            if not os.path.exists(pin_path):
                raise BPFPinObjNotFound(pin_path)
            need_reuse = True

        elif pin_map_flag == BPFObjectLoader.PIN_MAP_FLAG.PIN_IF_NOT_EXIST:
            if os.path.exists(pin_path):
                need_reuse = True
            else:
                need_pin = True
        else: 
            raise BPFLoadError("unkonwen pin map flag")

        if need_pin : 
            bpf_map__set_pin_path(bpf_map, pin_path)
            self.runtime_maps[name] = BPFLoaderBase.BPFRunTimeInfo(-1, True)
            return 
        
        if need_reuse:
            fd = bpf_obj_get(pin_path)
            bpf_map__reuse_fd(bpf_map, fd)

        self.runtime_maps[name] = BPFLoaderBase.BPFRunTimeInfo(-1, False)
        return 

    def __set_progs_type(self):
        for name, prog in self.progs.items(): 
            if not "prog_type" in prog:
                raise BPFLoadError("prog :%s without prog type"%name)
            prog_obj = bpf_object__find_program_by_name(self.bpf_obj, name)
            bpf_program__set_type(prog_obj, prog["prog_type"])

    def __pin_progs(self):
        for name, prog in self.progs.items(): 
            if not "pin_path" in prog :
                self.runtime_progs[name] = BPFLoaderBase.BPFRunTimeInfo(-1, False)
                continue 
            pin_path = prog["pin_path"]
            if os.path.exists(pin_path):
                raise BPFPinObjExist(pin_path)
            prog_obj = bpf_object__find_program_by_name(self.bpf_obj, name)
            bpf_program__pin(prog_obj, pin_path)
            self.runtime_progs[name] = BPFLoaderBase.BPFRunTimeInfo(-1, True)

class BPFBCCLoader(BPFLoaderBase): 
    def __init__(self, path, *, progs, pin_maps, cflags = [], unpin_only_fail = True,  **kw):
        '''
        compile bpf src file , load func and pin the func
        load bpf object using libbpf 
        @param:
            path: path to bpf object 
            progs: dict progs (all progs)
                prog_name : {
                    "prog_type" : BPF_PROG_TYPE
                    "pin_path" : "if pin prog"
                }
            pin_maps : maps to be pinned, key : map name value : 
                {
                    "pin_path" : pin path 
                    "flag" : pin_flag
                        BCC only support PIN_IF_NOT_EXIST
                        when create: 
                            3. PIN_IF_NOT_EXIST(if maps have been pinned reuse it else pin it)
                            default PIN_IF_NOT_EXIST
                            (BCC only support PIN_IF_NOT_EXIST)
                        when unpin: 
                            PIN_IF_NOT_EXIST depend on if pin object is created by loader
                } 
        '''
        super().__init__(progs = progs, pin_maps = pin_maps, unpin_only_fail = unpin_only_fail) 
        
        self.path = path 
        self.cflags = cflags

    @bpf_check_load
    def get_table(self, name):
        return self.bpf.get_table(name)

    @bpf_check_load
    def get_func(self, name):
        return self.funcs[name]
    
    def _load(self):
        self.funcs = {}
        self.__check_pin_maps()
        self.bpf = BPF(src_file = self.path, cflags = self.cflags)
        self.__set_pin_maps()
        self.__load_funcs_and_pin()

    def _get_map_runtime_info(self, name):
        if name in self.pin_maps:
            return BPFLoaderBase.BPFRunTimeInfo(bpf_obj_get(self.pin_maps[name]["pin_path"]), self.runtime_maps[name].pinned)
        return BPFLoaderBase.BPFRunTimeInfo(self.bpf.get_table(name).map_fd, False)
    
    def _get_prog_runtime_info(self, name):
        if not name in self.progs:
            raise RuntimeError("prog %s doesn't exists"%name)
        
        prog_info = self.progs[name]
        if "pin_path" in prog_info:
            return BPFLoaderBase.BPFRunTimeInfo(bpf_obj_get(prog_info["pin_path"]), self.runtime_progs[name].pinned)
        return BPFLoaderBase.BPFRunTimeInfo(self.funcs[name].fd, False)
    
    def __check_pin_maps(self):
        for name, map_info in self.pin_maps.items():
            flag = BPFLoaderBase.get_pin_map_flag(map_info)
            assert(flag == BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST)
            if os.path.exists(map_info["pin_path"]):
                self.runtime_maps[name] = BPFLoaderBase.BPFRunTimeInfo(-1, False)

    def __set_pin_maps(self):
        for name in self.pin_maps.keys():
            if  not name in self.runtime_maps:
                self.runtime_maps[name] = BPFLoaderBase.BPFRunTimeInfo(-1, True)

    def __load_funcs_and_pin(self):
        for name, prog_info in self.progs.items():
            if not "prog_type" in prog_info:
                raise RuntimeError("prog :%s without prog type"%name)
            func = self.bpf.load_func(name, prog_info["prog_type"])

            #pin func
            if "pin_path" in prog_info:
                bpf_obj_pin(func.fd, prog_info["pin_path"])
                self.runtime_progs[name] = BPFLoaderBase.BPFRunTimeInfo(-1, True)
            else:
                self.runtime_progs[name] = BPFLoaderBase.BPFRunTimeInfo(-1, False)
            self.funcs[name] = func

def load(bpf, loader, unpin_only_fail = True):
    if loader == BPFBCCLoader:
        path_key = "src_path"
    elif loader == BPFObjectLoader:
        path_key = "obj_path"
    else:
        raise RuntimeError("invalid loader")
    l = loader(bpf[path_key], progs = bpf["progs"], pin_maps = bpf["pin_maps"], unpin_only_fail = unpin_only_fail, **bpf["kw"])
    return l 

def get_name_idx_map(tail_call_list):
    name_idx_map = {}
    for list_idx, item in enumerate(tail_call_list):
        for name, idx in item["tail_call_map"].items():
            if name in name_idx_map:
                raise RuntimeError("failed to set name_idx_map, tail call name :%s exists"%name)
            val = {
                "tail_call_idx" : int(idx),
                "list_idx": int(list_idx)
            }
            name_idx_map[name] = val
    return name_idx_map

def get_idx_name_map(tail_call_list):
    idx_name_map = {}
    for list_idx, item in  enumerate(tail_call_list):
        for name, idx in item["tail_call_map"].items():
            if str(idx) in idx_name_map:
                raise RuntimeError("failed to set name_idx_map, tail call idx :%d exists"%idx)
            val = {
                "tail_call_name" : name,
                "list_idx" : list_idx
            }
            idx_name_map[str(idx)] = val
    return idx_name_map

class TailCallLoader: 
    def __init__(self, prog_array_fd, tail_call_list, loader = BPFBCCLoader, * , clear_only_fail = True):
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
        
        self.name_idx_map = get_idx_name_map(tail_call_list)
        self.prog_array_fd = prog_array_fd
        self.bpf_loaders = []
        self.tail_call_map = {}  # key : tail_call_index, value : fd 
        self.loaded_tail_call_map = {}
        self.clear_only_fail = clear_only_fail
        for item in tail_call_list:
            self.bpf_loaders.append(load(item, loader, unpin_only_fail=self.clear_only_fail))
    
    def __enter__(self):
        self.load()
        return self

    def __exit__(self, type, value, trace):
        fail = False 
        if type != None or value != None or trace != None:
            fail = True
            print("type: ", type)
            print("value: \n", value)
            print("trace: \n", trace)
        
        #if fail unpin 
        #if not fail unpin only when self.unpin_only_fail set False
        if fail or self.clear_only_fail == False:
            self.clear()

    def load(self):
        self._load_bpf_loader()
        self._set_tail_call_map()
        self._load_prog_array()
        self.loaded = True

    def clear(self):
        self._unload_prog_array()
        self._unpin()

    def _unload_prog_array(self):
        for key, _ in self.loaded_tail_call_map.items():
            tail_call_index = ct.c_int(int(key))
            bpf_map_delete_elem(self.prog_array_fd, ct.byref(tail_call_index))

    def _unpin(self):
        for loader in self.bpf_loaders:
            loader.unpin()

    def _load_bpf_loader(self):
        for bpf_loader in self.bpf_loaders:
            bpf_loader.load()

    def _set_tail_call_map(self):
        for idx_str, val in self.name_idx_map.items():
            list_idx = int(val["list_idx"])
            func_name = val["tail_call_name"]
            fd = self.bpf_loaders[list_idx].get_prog_fd(func_name)
            self.tail_call_map[idx_str] = fd

    def _load_prog_array(self):
        for key, fd in self.tail_call_map.items():
            tail_call_index = ct.c_int(int(key))
            fd_c = ct.c_int(fd)
            bpf_map_update_elem(self.prog_array_fd, ct.byref(tail_call_index), ct.byref(fd_c))
            self.loaded_tail_call_map[key] = fd
    
def unpin_maps(pin_maps):
    for _, map_info in pin_maps.items():
        flag = BPFLoaderBase.get_pin_map_flag(map_info)
        if flag != BPFLoaderBase.PIN_MAP_FLAG.REUSE:
            unpin(map_info["pin_path"])

def unpin_progs(progs):
    for _, prog_info in progs.items():
        if "pin_path" in prog_info:
            unpin(prog_info["pin_path"])

def unpin_obj(bpf_obj_info):
    unpin_progs(bpf_obj_info["progs"])
    unpin_maps(bpf_obj_info["pin_maps"])



    
    
    


    