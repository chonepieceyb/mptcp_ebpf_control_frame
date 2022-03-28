#-*- coding:utf-8 -*-

import ctypes as ct
from termios import VLNEXT 
from error import LinuxError
from config import CONFIG
from enum import IntFlag, IntEnum, unique

#enums 
@unique
class BPF_MAP_TYPE(IntEnum): 
    BPF_MAP_TYPE_UNSPEC = 0
    BPF_MAP_TYPE_HASH = 1
    BPF_MAP_TYPE_ARRAY = 2
    BPF_MAP_TYPE_PROG_ARRAY = 3
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
    BPF_MAP_TYPE_PERCPU_HASH = 5
    BPF_MAP_TYPE_PERCPU_ARRAY = 6
    BPF_MAP_TYPE_STACK_TRACE = 7
    BPF_MAP_TYPE_CGROUP_ARRAY = 8
    BPF_MAP_TYPE_LRU_HASH = 9
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10 
    BPF_MAP_TYPE_LPM_TRIE = 11
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12
    BPF_MAP_TYPE_HASH_OF_MAPS = 13
    BPF_MAP_TYPE_DEVMAP = 14
    BPF_MAP_TYPE_SOCKMAP = 15
    BPF_MAP_TYPE_CPUMAP = 16
    BPF_MAP_TYPE_XSKMAP = 17 
    BPF_MAP_TYPE_SOCKHASH = 18 
    BPF_MAP_TYPE_CGROUP_STORAGE = 19 
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20 
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21
    BPF_MAP_TYPE_QUEUE = 22
    BPF_MAP_TYPE_STACK = 23
    BPF_MAP_TYPE_SK_STORAGE = 24
    BPF_MAP_TYPE_DEVMAP_HASH = 25 
    BPF_MAP_TYPE_STRUCT_OPS = 26 
    BPF_MAP_TYPE_RINGBUF = 27 
    BPF_MAP_TYPE_INODE_STORAGE = 28 
    BPF_MAP_TYPE_TASK_STORAGE = 29 
    BPF_MAP_TYPE_BLOOM_FILTER = 30

# flags for BPF_MAP_CREATE command 
@unique 
class BPF_MAP_CREATE_FLAG(IntFlag):
    BPF_F_NO_PREALLOC	= 1 << 0
    
    #Instead of having one common LRU list in the
    #BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list
    #which can scale and perform better.
    #Note, the LRU nodes (including free nodes) cannot be moved
    #across different LRU lists.

    BPF_F_NO_COMMON_LRU = 1 << 1
    #Specify numa node during map creation 
    BPF_F_NUMA_NODE = 1 << 2

    #Flags for accessing BPF object from syscall side. 
    BPF_F_RDONLY    = 1 << 3
    BPF_F_WRONLY    = 1 << 4
    
    #Flag for stack_map, store build_id+offset instead of pointer 
    BPF_F_STACK_BUILD_ID	= 1<< 5
    
    #Zero-initialize hash function seed. This should only be used for testing. */
    BPF_F_ZERO_SEED		= 1 << 6

    #Flags for accessing BPF object from program side. 
    BPF_F_RDONLY_PROG	= 1 << 7
    BPF_F_WRONLY_PROG	= 1 << 8

    #Clone map from listener for newly accepted socket 
    BPF_F_CLONE	= 1 << 9

    # Enable memory-mapping BPF map 
    BPF_F_MMAPABLE  = 1 << 10

    #Share perf_event among processes */
    BPF_F_PRESERVE_ELEMS = 1 << 11

    #Create a map that is suitable to be an inner map with dynamic max entries */
    BPF_F_INNER_MAP	= 1 << 12

@unique
class BPF_MAP_UPDATE_ELEM_FLAG(IntFlag):
    BPF_ANY = 0
    BPF_NOEXIST = 1
    BPF_EXIST = 2
    BPF_F_LOCK  = 4

# funcs 
lib = ct.CDLL(CONFIG.libbpf_path, use_errno = True)

lib.bpf_obj_pin.restype = ct.c_int
lib.bpf_obj_pin.argtypes = [ct.c_int, ct.c_char_p]

lib.bpf_obj_get.restype = ct.c_int 
lib.bpf_obj_get.argtypes = [ct.c_char_p]

lib.bpf_map_update_elem.restype = ct.c_int
lib.bpf_map_update_elem.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p, ct.c_uint64]

lib.bpf_map_delete_elem.restype = ct.c_int 
lib.bpf_map_delete_elem.argtypes = [ct.c_int, ct.c_void_p]

lib.bpf_map_lookup_elem.restype = ct.c_int 
lib.bpf_map_lookup_elem.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p]

lib.bpf_create_map.restype = ct.c_int 
lib.bpf_create_map.argtypes = [ct.c_int, ct.c_int, ct.c_int, ct.c_int, ct.c_uint32]

lib.libbpf_get_error.restype = ct.c_long
lib.libbpf_get_error.argtypes = [ct.c_void_p]

lib.libbpf_strerror.restype = ct.c_int
lib.libbpf_strerror.argtypes = [ct.c_int, ct.c_char_p, ct.c_size_t]

perf_buffer_sample_fn = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_int, ct.c_void_p, ct.c_uint32) # (void*  ctx, int cpu, void* data, __u32 size)
perf_buffer_lost_fn = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_int, ct.c_uint64) # void* ctx , int cpu, __u64 cnt


lib.perf_buffer__new.restype = ct.c_void_p
lib.perf_buffer__new.argtypes = [ct.c_int, ct.c_size_t, perf_buffer_sample_fn, perf_buffer_lost_fn, ct.c_void_p, ct.c_void_p]

lib.perf_buffer__free.restype = None 
lib.perf_buffer__free.argtypes = [ct.c_void_p]

lib.perf_buffer__poll.restype = ct.c_int
lib.perf_buffer__poll.argtypes = [ct.c_void_p, ct.c_int]

lib.bpf_object__open.restype = ct.c_void_p
lib.bpf_object__open.argtypes = [ct.c_char_p]

lib.bpf_object__load.restype = ct.c_int 
lib.bpf_object__load.argtypes = [ct.c_void_p]

lib.bpf_object__pin.restype = ct.c_int 
lib.bpf_object__pin.argtypes = [ct.c_void_p, ct.c_char_p]

lib.bpf_object__find_program_by_name.restype = ct.c_void_p
lib.bpf_object__find_program_by_name.argtypes = [ct.c_void_p, ct.c_char_p]

lib.bpf_program__fd.restype = ct.c_int
lib.bpf_program__fd.argtypes = [ct.c_void_p]

lib.bpf_object__find_map_by_name.restype = ct.c_void_p
lib.bpf_object__find_map_by_name.argtypes = [ct.c_void_p, ct.c_char_p]

lib.bpf_map__fd.restype = ct.c_int
lib.bpf_map__fd.argtypes = [ct.c_void_p]

lib.bpf_map__pin.restype = ct.c_int
lib.bpf_map__pin.argtypes = [ct.c_void_p, ct.c_char_p]

lib.bpf_program__pin.restype = ct.c_int
lib.bpf_program__pin.argtypes = [ct.c_void_p, ct.c_char_p]

lib.bpf_map__reuse_fd.restype = ct.c_int
lib.bpf_map__reuse_fd.argtypes = [ct.c_void_p, ct.c_int]

#errors 

class LibbpfError(Exception):
    def __init__(self, hint, errno):
        super().__init__(self) #初始化父类
        self.errorinfo= "%s, libbpf err: %d, %s"%(hint, errno, libbpf_strerror(errno))
        self.errno = errno

    def __str__(self):
        return self.errorinfo

def check_res(hint, res): 
    if res < 0: 
        raise LinuxError(hint, ct.get_errno())

def check_libpfres(hint, res): 
    if res < 0: 
        raise LibbpfError(hint, res)

#python func wrapper for easy usage 
def bpf_obj_pin(fd, pathname):
    '''
    @param:
        fd: bpf object fd 
        pathname : path in bpf virtual file system(str)
    '''
    res = lib.bpf_obj_pin(ct.c_int(fd), pathname.encode(encoding = "utf-8"))
    check_res("bpf_obj_pin", res)

def bpf_obj_get(pathname) : 
    '''
    @param:
        pathname: path of bpf object pinned to bpf virtual filesystem (const char*)
    @return:
        fd of bpf object if success or raise LinuxError
    '''
    fd = lib.bpf_obj_get(pathname.encode(encoding = "utf-8"))
    check_res("bpf_obj_get", fd)
    return fd 

def bpf_map_update_elem(fd, key, value, flags = BPF_MAP_UPDATE_ELEM_FLAG.BPF_ANY):
    '''
    @param:
        fd : bpf map fd (int)
        key: ctypes pointer object (const void*)
        value: ctypes pointer object (const void*)
        flags: BPF_MAP_UPDATE_ELEM_FLAGS
    '''
    res = lib.bpf_map_update_elem(ct.c_int(fd), key, value, ct.c_uint64(flags))
    check_res("bpf_map_update_elem",res)

def bpf_map_delete_elem(fd, key):
    '''
    @param: 
        fd : bpf map fd 
        key : ctypes pointer object (const void*)
    '''
    res = lib.bpf_map_delete_elem(ct.c_int(fd), key)
    check_res("bpf_map_delete_elem", res)

def bpf_map_lookup_elem(fd, key , value):
    '''
    @param
        fd : bpf map fd  (int)
        key : ctypes pointer key (const void*)
        value : ctypes pointer value (void *)
    '''
    res = lib.bpf_map_lookup_elem(ct.c_int(fd), key, value)
    check_res("bpf_map_delete_elem", res)

def bpf_create_map(map_type, key_size, value_size, max_entries, map_flags = 0):
    '''
    @param
        map_type: bpf_map_type
        key_size: key size(bytes) (int)
        value_size: value size(bytes)(int)
        max_entries: max entries (int)
        map_flags : bpf map create flags 
    @return
        map fd on success 
    '''
    fd = lib.bpf_create_map(ct.c_int(map_type), \
        ct.c_int(key_size), ct.c_int(value_size), \
        ct.c_int(max_entries), ct.c_uint32(map_flags))
    check_res("bpf_create_map", fd)
    return fd

def libbpf_strerror(err): 
    BUFFER_SIZE = 40
    buf = ct.create_string_buffer(BUFFER_SIZE)
    lib.libbpf_strerror(ct.c_int(err), buf, ct.c_size_t(BUFFER_SIZE))
    return buf.value

def bpf_object__open(path):
    '''
    @param: path of the bpf object path 
    @return bpf_object pointer
    '''
    bpf_obj = lib.bpf_object__open(path.encode(encoding = "utf-8"))
    if bpf_obj == None: 
        raise LinuxError("bpf_object__open failed", ct.get_errno())
    return bpf_obj

def bpf_object__load(bpf_obj):
    '''
    @param: bpf_obj , bpf object pointer get from bpf_object__open, load bpf objects(maps and progs) into kernnel 
    '''
    res = lib.bpf_object__load(bpf_obj)
    check_res("bpf_object__load failed", res)

def bpf_object__pin(bpf_obj, path):
    '''
    @param
        bpf_obj : bpf object pointer
        path: pin root path 
    '''
    res = lib.bpf_object__pin(bpf_obj, path.encode(encoding = "utf-8"))
    check_libpfres("bpf_object__pin failed", res)

def bpf_object__find_program_by_name(bpf_obj, name):
    '''
    @param: 
        bpf_obj: bpf object 
        name: name of program 
    @return 
        prog pointer
    '''
    prog = lib.bpf_object__find_program_by_name(bpf_obj, name.encode(encoding = "utf-8"))
    res = lib.libbpf_get_error(prog)
    check_libpfres("bpf_object__find_program_by_name failed", res)
    return prog

def bpf_program__fd(bpf_prog):
    '''
    @param:
        bpf_prog: bpf prog object get from bpf_object__find_program_by_name
    return: 
        prog fd 
    '''
    res = lib.bpf_program__fd(bpf_prog)
    check_libpfres("bpf_program__fd failed", res)
    return res

def bpf_object__find_map_by_name(bpf_obj, name):
    '''
    @param: 
        bpf_obj: bpf object 
        name: name of program 
    return:
        program object 
    '''
    m = lib.bpf_object__find_map_by_name(bpf_obj, name.encode(encoding = "utf-8"))
    res = lib.libbpf_get_error(m)
    check_libpfres("bpf_object__find_map_by_name failed", res)
    return m

def bpf_map__fd(bpf_map):
    '''
    @param:
        bpf_map: bpf map object get from bpf_object__find_program_by_name
    return: 
        map fd 
    '''
    res = lib.bpf_map__fd(bpf_map)
    check_libpfres("bpf_map__fd failed", res)
    return res

def bpf_map__pin(bpf_map, path):
    '''
    @param:
        bpf_map: bpf map object get from bpf_object__find_program_by_name
        path: pin path
    '''
    
    res = lib.bpf_map__pin(bpf_map, path.encode(encoding = "utf-8"))
    print(res)
    check_libpfres("bpf_map__pin failed", res)

def bpf_program__pin(bpf_prog, path):
    '''
    @param:
        bpf_prog: bpf prog object get from bpf_object__find_program_by_name
        path: pin path
    '''
    res = lib.bpf_program__pin(bpf_prog, path.encode(encoding = "utf-8"))
    check_libpfres("bpf_program__pin failed", res)

def bpf_map__reuse_fd(bpf_map, fd):
    '''
    @param:
        bpf_map: map object 
        fd: fd to be reused 
    '''
    res = lib.bpf_map__reuse_fd(bpf_map, ct.c_int(fd))
    check_libpfres("bpf_map__reuse_fd failed", res)
    
#perf buffer 
class PerfBuffer:
    def __init__(self, fd, cb, lost_cb = None, *, page_cnt = 8) :
        self.page_cnt = page_cnt
        self.fd = fd
        if lost_cb == None: 
            self.lost_cb = perf_buffer_lost_fn()
        else:
            self.lost_cb  = perf_buffer_lost_fn(lost_cb)

        self.sample_cb = perf_buffer_sample_fn(cb)
        self.ctx = ct.c_void_p(None)
     
    def __enter__(self):
        self.pb = lib.perf_buffer__new(ct.c_int(self.fd), ct.c_size_t(self.page_cnt), self.sample_cb, self.lost_cb, self.ctx, ct.c_void_p(None))
        err = lib.libbpf_get_error(self.pb)
        if err != 0 :
            raise LibbpfError("open perf buffer failed", err)
        return self 

    def __exit__(self, type, value, trace):
        print ("type:", type)
        print ("value:", value)
        print ("trace:", trace)
        lib.perf_buffer__free(self.pb)

    def poll(self, timeout_ms = 1): 
        lib.perf_buffer__poll(self.pb, ct.c_int(timeout_ms))

# testing 
if __name__ == '__main__' : 
    import os 
    from common import *
    '''
    try : 
        path = os.path.join("/sys/fs/bpf/tc/globals", "test_perf_array")                                                                      
        #test pin 
        if not os.path.exists(path):
            #create bpf map first 
            fd = bpf_create_map(BPF_MAP_TYPE.BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4 , 4, 2)
            print("fd : %d"%fd)              
            bpf_obj_pin(fd, path)

        #get fd 
        nfd = bpf_obj_get(path)

        def print_event(ctx, cpu, data, size):
            print("get perf event code")

        print(print_event)
        print("new fd: %d"%nfd)
        
        with PerfBuffer(nfd, print_event, page_cnt=8) as pb : 
            while True : 
                pb.poll()

    except LibbpfError as e : 
        print(e)

    '''
    try:
        tail_path = os.path.join(BPF_TC_BTF_OBJS_PATH, "tc_egress_tailcall.c.o")
        tail_obj = bpf_object__open(tail_path)
        bpf_object__load(tail_obj)

    except LibbpfError as e : 
        print(e)