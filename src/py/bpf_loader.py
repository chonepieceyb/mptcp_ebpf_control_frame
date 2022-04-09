#-*- coding:utf-8 -*-
from bcc import BPF
import os
from abc import abstractmethod

from libbpf import *
from utils import unpin
from error import *
from enum import IntEnum, unique

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

    def __init__(self, *, progs, pin_maps):
        self.runtime_progs = {}    
        self.runtime_maps = {}    
        self.progs = progs
        self.pin_maps = pin_maps 
       
    def unpin_maps(self):
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
    
    def unpin_progs(self):
        for name , rt_info in self.runtime_progs.items():
            if not rt_info.pinned:
                continue
            try:
                prog_info = self.progs[name]
                print("unpin: %s"%prog_info["pin_path"])
                unpin(prog_info["pin_path"], None)
            except Exception as e:
                print(e)
    
    #回收bpf资源
    def unpin(self):
        self.unpin_maps()
        self.unpin_progs()

    def get_map_fd(self, name):
        if name in self.runtime_maps and self.runtime_maps[name].fd >= 0:
            return self.runtime_maps[name].fd
        rt_info = self._get_map_runtime_info(name)
        self.runtime_maps[name] = rt_info
        return rt_info.fd
    
    def get_prog_fd(self, name):
        if name in self.runtime_progs and self.runtime_progs[name].fd >= 0:
            return self.runtime_progs[name].fd
        rt_info = self._get_prog_runtime_info(name)
        self.runtime_progs[name] = rt_info
        return rt_info.fd

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
        for name, prog_info in self.progs.items(): 
            if not "pin_path" in prog_info: 
                continue 
            pin_path = prog_info["pin_path"]
            fd = bpf_obj_get(pin_path)
            self.runtime_progs[name] = BPFLoaderBase.BPFRunTimeInfo(fd, True)
            
        for name, map_info in self.pin_maps.items(): 
            fd = bpf_obj_get(map_info["pin_path"])
            self.runtime_maps[name] = BPFLoaderBase.BPFRunTimeInfo(fd, True)

    def _get_map_runtime_info(self, name):
        raise BPFLoadError("BPFPINLoader only load pinned map")

    def _get_prog_runtime_info(self, name):
        raise BPFLoadError("BPFPINLoader only load pinned prog")

    def unpin_maps(self):
        raise BPFLoadError("BPFPINLoader not support unpin maps")

    def unpin_progs(self):
        raise BPFLoadError("BPFPINLoader not support unpin progs")
    
    def unpin(self):
        raise BPFLoadError("BPFPINLoader not support unpin")

class BPFObjectLoader(BPFLoaderBase):
    def __init__(self, path, *, progs, pin_maps, **kw):
        super().__init__(progs = progs, pin_maps = pin_maps)
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
        try:
            self.bpf_obj = bpf_object__open(os.path.abspath(path))
            self.__load()
        except Exception as e:
            print("faild to init BPFObjectLoader", e)
            self.unpin()  #不好定义析构函数 定义在这
            raise e
            
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

    def __load(self):
        self.__pin_maps()
        self.__set_progs_type()
        bpf_object__load(self.bpf_obj)   #load bpf object
        self.__pin_progs()               #pin progs

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
    def __init__(self, path, *, progs, pin_maps, cflags = [], **kw):
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
        super().__init__(progs = progs, pin_maps = pin_maps) 
        
        try:
            self.funcs = {}
            self.__check_pin_maps()
            self.bpf = BPF(src_file = path, cflags = cflags)
            self.__set_pin_maps()
            self.__load_funcs_and_pin()
        except Exception as e: 
            self.unpin() 
            raise e

    def get_table(self, name):
        return self.bpf.get_table(name)

    def get_func(self, name):
        return self.funcs[name]
    
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

# test program 
if __name__ == '__main__': 
    from common import *
    
    XDP_ACTIONS = "xdp_actions"
    XDP_ACTIONS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_ACTIONS)
    SUBFLOW_ACTION_INGRESS = "subflow_action_ingress"
    SUBFLOW_ACTION_INGRESS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, SUBFLOW_ACTION_INGRESS)
    test_prog = {
        "src_path" : os.path.join(XDP_PROG_PATH, "xdp_main.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "xdp_main.c.o"),
        "progs" : {
            "xdp_main" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP,
                "pin_path" : "/sys/fs/bpf/mptcp_ebpf_control_frame/xdp_main"
            }
        },
        "pin_maps" : {
            "xdp_actions" : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN
            },
            "subflow_action_ingress": {
                "pin_path" : SUBFLOW_ACTION_INGRESS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g", "-O2"]
        }
    }

    test_prog2 = {
        "src_path" : os.path.join(XDP_PROG_PATH, "xdp_main.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "xdp_main.c.o"),
        "progs" : {
            "xdp_main" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            "xdp_actions" : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            "subflow_action_ingress": {
                "pin_path" : SUBFLOW_ACTION_INGRESS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g", "-O2"]
        }
    }

    test_prog3 = {
        "src_path" : os.path.join(XDP_PROG_PATH, "xdp_main.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "xdp_main.c.o"),
        "progs" : {
            "xdp_main" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            "xdp_actions" : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.REUSE
            },
            "subflow_action_ingress": {
                "pin_path" : SUBFLOW_ACTION_INGRESS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.REUSE
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g", "-O2"]
        }
    }


    '''
        obj_loader = None 
        obj_loader2 = None
        obj_loader3 = None
        print("test bpf object loader")
        try :
            

            obj_loader = BPFObjectLoader(test_prog["obj_path"], progs = test_prog["progs"], pin_maps = test_prog["pin_maps"])
            print("actions fd%s"%obj_loader.get_map_fd("xdp_actions"))
            print("subflows fd%s"%obj_loader.get_map_fd("subflow_action_ingress"))
            print("xdp mian fd%s"%obj_loader.get_prog_fd("xdp_main"))

            obj_loader2 = BPFObjectLoader(test_prog2["obj_path"], progs = test_prog2["progs"], pin_maps = test_prog2["pin_maps"])
            print("actions fd%s"%obj_loader2.get_map_fd("xdp_actions"))
            print("subflows fd%s"%obj_loader2.get_map_fd("subflow_action_ingress"))
            print("xdp mian fd%s"%obj_loader2.get_prog_fd("xdp_main"))

            #load by object
            obj_loader3 = BPFObjectLoader(test_prog3["obj_path"], progs = test_prog3["progs"], pin_maps = test_prog3["pin_maps"])
            print("actions fd%s"%obj_loader3.get_map_fd("xdp_actions"))
            print("subflows fd%s"%obj_loader3.get_map_fd("subflow_action_ingress"))
            print("xdp mian fd%s"%obj_loader3.get_prog_fd("xdp_main"))
            while True: 
                try :
                    pass
                except KeyboardInterrupt:
                    if obj_loader != None: 
                        obj_loader.unpin()
                    if obj_loader2 != None: 
                        obj_loader2.unpin()  
                    if obj_loader3 != None: 
                        obj_loader3.unpin()  
                    exit()

        except Exception as e: 
            if obj_loader != None: 
                obj_loader.unpin()
            if obj_loader2 != None: 
                obj_loader2.unpin()  
            if obj_loader3 != None: 
                obj_loader2.unpin()  
            print(e)
    '''

    print("test bcc loader")
    bcc_loader2 = None 
    
    try :
    
        bcc_loader2 = BPFBCCLoader(test_prog2["src_path"], progs = test_prog2["progs"], pin_maps = test_prog2["pin_maps"],  cflags = ["-I%s"%SRC_BPF_KERN_PATH, "-g", "-O2"])
        print("actions fd%s"%bcc_loader2.get_map_fd("xdp_actions"))
        print("subflows fd%s"%bcc_loader2.get_map_fd("subflow_action_ingress"))
        print("xdp mian fd%s"%bcc_loader2.get_prog_fd("xdp_main"))
        
        #test pin loader 
        print("test pin loader")
        pin_loader = BPFPINLoader(progs = test_prog2["progs"], pin_maps = test_prog2["pin_maps"])
        print("actions fd%s"%pin_loader.get_map_fd("xdp_actions"))
        print("subflows fd%s"%pin_loader.get_map_fd("subflow_action_ingress"))
        while True: 
            try :
                pass
            except KeyboardInterrupt:
                unpin_obj(test_prog2)
                exit()

    except Exception as e: 
        if bcc_loader2 != None: 
            bcc_loader2.unpin()  
        print(e)

    

    
    
    


    