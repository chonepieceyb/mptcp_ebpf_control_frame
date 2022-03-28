#-*- coding:utf-8 -*-
from bcc import BPF
import os 
from libbpf import bpf_obj_pin
import ctypes as ct 
from config import CONFIG

class BPFFuncLoader:  
    def __init__(self, path, prog_type, func_name = None, *, cflags = []): 
        '''
        compile bpf src file , load func and pin the func
        param: 
            path: path of the .c file 
            func_name: func to be load 
            cflags: compile flags 
            ps: one bpf program one file
        '''
        self.path = os.path.abspath(path)
        self.prog_type = prog_type
        self.cflags = cflags 
        self.func_name = func_name 
        if func_name == None: 
            self._get_func_name()
        self.bpf = BPF(src_file = self.path, cflags = self.cflags)
        self._load_func()

    #pin func object to bpf file system 
    def pin(self, name = None):
        if name == None : 
            name = self.func_name 
        self.pin_path = os.path.join(CONFIG.bpf_virtual_fs_path, name)
        bpf_obj_pin(self.fd, self.pin_path)

    def _get_func_name(self):
        _, filename = os.path.split(self.path)
        self.func_name, _ = os.path.splitext(filename)
    
    def _load_func(self): 
        self.func = self.bpf.load_func(self.func_name, self.prog_type)
        self.fd = self.func.fd

   
# test program 
if __name__ == '__main__': 
    # test 
    import sys
    file = sys.argv[1]
    f = BPFFuncLoader(file, BPF.XDP)
    f.pin()