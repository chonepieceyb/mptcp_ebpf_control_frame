#-*- coding:utf-8 -*-

import ctypes as ct
from error import LinuxError
from enum import IntFlag, IntEnum, unique
from common import LIBBPF_SO_PATH

def setzero(c_type_object):
    ct.memset(ct.byref(c_type_object), ct.c_int(0), ct.sizeof(c_type_object))
#enums 
@unique
class BPF_PROG_TYPE(IntEnum):
	BPF_PROG_TYPE_UNSPEC = 0
	BPF_PROG_TYPE_SOCKET_FILTER = 1
	BPF_PROG_TYPE_KPROBE = 2
	BPF_PROG_TYPE_SCHED_CLS = 3
	BPF_PROG_TYPE_SCHED_ACT = 4
	BPF_PROG_TYPE_TRACEPOINT = 5
	BPF_PROG_TYPE_XDP = 6
	BPF_PROG_TYPE_PERF_EVENT = 7
	BPF_PROG_TYPE_CGROUP_SKB = 8
	BPF_PROG_TYPE_CGROUP_SOCK = 9
	BPF_PROG_TYPE_LWT_IN = 10
	BPF_PROG_TYPE_LWT_OUT = 11
	BPF_PROG_TYPE_LWT_XMIT = 12
	BPF_PROG_TYPE_SOCK_OPS = 13
	BPF_PROG_TYPE_SK_SKB = 14
	BPF_PROG_TYPE_CGROUP_DEVICE = 15
	BPF_PROG_TYPE_SK_MSG = 16
	BPF_PROG_TYPE_RAW_TRACEPOINT = 17
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18
	BPF_PROG_TYPE_LWT_SEG6LOCAL = 19
	BPF_PROG_TYPE_LIRC_MODE2 = 20
	BPF_PROG_TYPE_SK_REUSEPORT = 21
	BPF_PROG_TYPE_FLOW_DISSECTOR = 22
	BPF_PROG_TYPE_CGROUP_SYSCTL = 23
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE= 24
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25
	BPF_PROG_TYPE_TRACING = 26
	BPF_PROG_TYPE_STRUCT_OPS = 27
	BPF_PROG_TYPE_EXT = 28
	BPF_PROG_TYPE_LSM = 29
	BPF_PROG_TYPE_SK_LOOKUP = 30
	BPF_PROG_TYPE_SYSCALL = 31 

@unique
class XDP_FLAGS(IntEnum):
    XDP_FLAGS_UPDATE_IF_NOEXIST =   (1 << 0)
    XDP_FLAGS_SKB_MODE =            (1 << 1)
    XDP_FLAGS_DRV_MODE = 	        (1 << 2)
    XDP_FLAGS_HW_MOD = 	            (1 << 3)
    XDP_FLAGS_REPLACE = 		    (1 << 4)

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
lib = ct.CDLL(LIBBPF_SO_PATH, use_errno = True)

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

lib.bpf_map_lookup_and_delete_elem.restype = ct.c_int 
lib.bpf_map_lookup_and_delete_elem.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p] 

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

lib.bpf_object__close.restype = None 
lib.bpf_object__close.argtypes = [ct.c_void_p]

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

lib.bpf_map__set_pin_path.restype = ct.c_int 
lib.bpf_map__set_pin_path.argtypes = [ct.c_void_p, ct.c_char_p]

lib.bpf_program__set_type.restype = None 
lib.bpf_program__set_type.argtypes = [ct.c_void_p, ct.c_int]

lib.bpf_xdp_attach.restype = ct.c_int
lib.bpf_xdp_attach.argtypes = [ct.c_int, ct.c_int, ct.c_uint32, ct.c_void_p]

lib.bpf_xdp_detach.restype = ct.c_int
lib.bpf_xdp_detach.argtypes = [ct.c_int, ct.c_uint32, ct.c_void_p]

lib.bpf_link__disconnect.restype = None 
lib.bpf_link__disconnect.argtypes = [ct.c_void_p]

lib.bpf_link__destroy.restype = ct.c_int  
lib.bpf_link__destroy.argtypes = [ct.c_void_p]

lib.bpf_link__pin.restype = ct.c_int  
lib.bpf_link__pin.argtypes = [ct.c_void_p, ct.c_char_p]

lib.bpf_program__attach_kprobe.restype = ct.c_void_p
lib.bpf_program__attach_kprobe.argtypes = [ct.c_void_p, ct.c_bool, ct.c_char_p]

lib.bpf_program__name.restype = ct.c_char_p
lib.bpf_program__name.argtypes = [ct.c_void_p]

lib.bpf_map__name.restype = ct.c_char_p
lib.bpf_map__name.argtypes = [ct.c_void_p]

lib.bpf_map__set_map_extra.restype = ct.c_int
lib.bpf_map__set_map_extra.argtypes = [ct.c_void_p, ct.c_uint64]

class xdp_md(ct.Structure):
    _fields_ = [    \
        ("data", ct.c_uint32),\
        ("data_end", ct.c_uint32),\
        ("data_meta", ct.c_uint32),\
        ("ingress_ifindex", ct.c_uint32),\
        ("rx_queue_index", ct.c_uint32),\
        ("egress_ifindex", ct.c_uint32),\
    ]

class bpf_test_run_ops(ct.Structure):
    _fields_  = [\
        ("sz", ct.c_uint64),\
        ("data_in", ct.c_void_p),\
        ("data_out", ct.c_void_p),\
        ("data_size_in", ct.c_uint32),\
        ("data_size_out", ct.c_uint32),\
        ("ctx_in", ct.c_void_p),\
        ("ctx_out", ct.c_void_p),\
        ("ctx_size_in", ct.c_uint32),\
        ("ctx_size_out", ct.c_uint32),\
        ("retval", ct.c_uint32),\
        ("repeat", ct.c_int),\
        ("duration", ct.c_uint32),\
        ("flags", ct.c_uint32),\
        ("cpu", ct.c_uint32),\
        ("batch_size", ct.c_uint32),\
    ]

lib.bpf_prog_test_run_opts.restype = ct.c_int 
lib.bpf_prog_test_run_opts.argtypes = [ct.c_int, ct.c_void_p]

@unique
class BPF_TC_FLAGS(IntFlag):
    BPF_TC_F_REPLACE = 1 << 0

@unique 
class BPF_TC_ATTACH_POINT(IntFlag):
    BPF_TC_INGRESS = 1 << 0
    BPF_TC_EGRESS = 1 << 1
    BPF_TC_CUSTOM = 1 << 2

class bpf_tc_hook(ct.Structure):
     _fields_  = [\
        ("sz", ct.c_size_t),
        ("ifindex", ct.c_int),
        ("attach_point", ct.c_int),
        ("parent", ct.c_uint32)
    ]

def init_libbpf_opt(OPT, **kw):
    opt = OPT()
    opt.sz = ct.sizeof(OPT)
    for a, v in kw.items():
        setattr(opt, a, v)
    return opt

class bpf_tc_opts(ct.Structure):
     _fields_  = [\
        ("sz", ct.c_size_t),
        ("prog_fd", ct.c_int),
        ("flags", ct.c_uint32),
        ("prog_id", ct.c_uint32),
        ("handle", ct.c_uint32),
        ("priority", ct.c_uint32)
    ]

lib.bpf_tc_hook_create.restype = ct.c_int 
lib.bpf_tc_hook_create.argtypes = [ct.c_void_p]

lib.bpf_tc_hook_destroy.restype = ct.c_int 
lib.bpf_tc_hook_destroy.argtypes = [ct.c_void_p]

lib.bpf_tc_attach.restype = ct.c_int 
lib.bpf_tc_attach.argtypes = [ct.c_void_p, ct.c_void_p]

lib.bpf_tc_detach.restype = ct.c_int 
lib.bpf_tc_detach.argtypes = [ct.c_void_p, ct.c_void_p]

#struct ops attact
lib.bpf_map__attach_struct_ops.restype = ct.c_void_p
lib.bpf_map__attach_struct_ops.argtypes = [ct.c_void_p]

#for mod struct_ops
#lib.bpf_map__set_struct_ops_module.restype = ct.c_int 
#lib.bpf_map__set_struct_ops_module.argtypes = [ct.c_void_p, ct.c_char_p]

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

def check_errno(hint, errno):
    if errno < 0: 
        raise LinuxError(hint, errno)

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
    check_res("bpf_obj_get: %s"%pathname, fd)
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
    check_res("bpf_map_lookup_elem", res)

def bpf_map_lookup_and_delete_elem(fd, key, value):
    '''
    @param
        fd : bpf map fd  (int)
        key : ctypes pointer key (const void*)
        value : ctypes pointer value (void *)
    '''
    res = lib.bpf_map_lookup_and_delete_elem(ct.c_int(fd), key, value)
    check_res("bpf_map_lookup_and_delete_elem", res)

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
    
def bpf_object__close(bpf_obj):
    '''
    @param: loaded bpf_obj 
    '''
    lib.bpf_object__close(bpf_obj)

def bpf_object__pin(bpf_obj, path):
    '''
    @param
        bpf_obj : bpf object pointer
        path: pin root path 
    '''
    res = lib.bpf_object__pin(bpf_obj, path.encode(encoding = "utf-8"))
    check_libpfres("bpf_object__pin : %s failed"%path, res)

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
    check_libpfres("bpf_object__find_program_by_name : %s failed"%name, res)
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
    check_libpfres("bpf_object__find_map_by_name :%s failed"%name, res)
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
    check_libpfres("bpf_map__pin : %s failed"%path, res)

def bpf_program__pin(bpf_prog, path):
    '''
    @param:
        bpf_prog: bpf prog object get from bpf_object__find_program_by_name
        path: pin path
    '''
    res = lib.bpf_program__pin(bpf_prog, path.encode(encoding = "utf-8"))
    check_libpfres("bpf_program__pin : %s failed"%path, res)

def bpf_map__reuse_fd(bpf_map, fd):
    '''
    @param:
        bpf_map: map object 
        fd: fd to be reused 
    '''
    res = lib.bpf_map__reuse_fd(bpf_map, ct.c_int(fd))
    check_libpfres("bpf_map__reuse_fd failed", res)

def bpf_map__set_pin_path(bpf_map, path):
    '''
    @param:
        bpf_map: map object 
        path path to be pinned 
    '''
    res = lib.bpf_map__set_pin_path(bpf_map, path.encode(encoding = "utf-8"))
    check_libpfres("bpf_map__set_pin_path failed", res)

def bpf_program__set_type(prog, type):
    '''
    @param:
        prog: prog object 
        type: prog type
    '''
    lib.bpf_program__set_type(prog, ct.c_int(type))

def bpf_xdp_attach(ifindex, prog_fd, flags, opts = ct.c_void_p(None)):
    '''
    @param
        ifindex : dev if index, ifindex can got by name using socket.if_nametoindex func 
        prog_fd : xdp prog fd 
        flags : 

        opts: 
            const struct bpf_xdp_attach_opts 
    '''
    res = lib.bpf_xdp_attach(ct.c_int(ifindex), ct.c_int(prog_fd), ct.c_uint32(flags), opts)
    check_libpfres("bpf_xdp_attach failed", res)

def bpf_xdp_detach(ifindex, flags, opts = ct.c_void_p(None)):
    '''
    @param
        ifindex : dev if index, ifindex can got by name using socket.if_nametoindex func 
        prog_fd : xdp prog fd 
        flags : 

        opts: 
            const struct bpf_xdp_attach_opts 
    '''
    res = lib.bpf_xdp_detach(ct.c_int(ifindex), ct.c_uint32(flags), opts)
    check_libpfres("bpf_xdp_attach failed", res)

def bpf_tc_hook_create(hook):
    '''
    @param:
        hook : tc hook 
    '''
    res = lib.bpf_tc_hook_create(ct.byref(hook))
    check_libpfres("bpf_tc_hook_create failed", res)

def bpf_tc_hook_destroy(hook):
    res = lib.bpf_tc_hook_destroy(ct.byref(hook))
    check_libpfres("bpf_tc_hook_destory failed", res)

def bpf_tc_attach(hook, opts):
    '''
    @param: 
        hook: bpf tc hook 
        opts: tc opts
    '''

    res = lib.bpf_tc_attach(ct.byref(hook), ct.byref(opts))
    check_libpfres("bpf_tc_attach failed", res)

def bpf_tc_detach(hook, opts):
    res = lib.bpf_tc_detach(ct.byref(hook), ct.byref(opts))
    check_libpfres("bpf_tc_detach failed", res)

def bpf_link__disconnect(bpf_link):
    lib.bpf_link__disconnect(bpf_link)
    
def bpf_link__destroy(bpf_link):
    res = lib.bpf_link__destroy(bpf_link)
    check_libpfres("bpf_link__destroy failed", res)


def bpf_link__pin(bpf_link, path):
    '''
    @param:
        bpf_link: bpf_link object get from the result of attach
        path: pin path
    '''
    res = lib.bpf_link__pin(bpf_link, path.encode(encoding = "utf-8"))
    check_libpfres("bpf_link__pin : %s failed"%path, res)

def bpf_program__name(bpf_prog):
    name = lib.bpf_program__name(bpf_prog)
    return name.decode("utf-8")

def bpf_map__name(bpf_map):
    name = lib.bpf_map__name(bpf_map)
    return name.decode("utf-8")

def bpf_program__attach_kprobe(bpf_program, retprobe, func_name):
    link = lib.bpf_program__attach_kprobe(bpf_program, ct.c_bool(retprobe), func_name.encode(encoding = "utf-8"))
    res = lib.libbpf_get_error(link)
    check_libpfres("bpf_program__attach_kprobe failed to attach prog %s to %s with retprobe = %s"%(bpf_program__name(bpf_program), func_name, str(retprobe)), res)
    return link

def bpf_map__attach_struct_ops(bpf_map):
    link = lib.bpf_map__attach_struct_ops(bpf_map)
    res = lib.libbpf_get_error(link)
    check_libpfres("bpf_map__attach_struct_ops failed to attach map %s"%(bpf_map__name(bpf_map)), res)
    return link

'''
def bpf_map__set_struct_ops_module(bpf_map, module_name):
    res = lib.bpf_map__set_struct_ops_module(bpf_map, ct.c_char_p(module_name.encode("ascii")))
    check_libpfres("bpf_map_struct_ops_module %s failed to set module name %s"%(bpf_map__name(bpf_map), module_name), res)
'''

def bpf_map__set_map_extra(bpf_map, map_extra):
    res = lib.bpf_map__set_map_extra(bpf_map, ct.c_uint64(map_extra))
    check_libpfres("failed to set bpf_map %s extra"%bpf_map__name(bpf_map), res)

BPF_F_TEST_XDP_LIVE_FRAMES = 1 << 1

def bpf_prog_test_run_opts(prog_fd, opts):
    res = lib.bpf_prog_test_run_opts(ct.c_int(prog_fd), opts)
    check_libpfres("bpf_prog_test_run with prog %d failed "%prog_fd, res)

def memset(ct_obj, v):
    ct.memset(ct.byref(ct_obj), ct.c_int(v), ct.sizeof(ct_obj))

# testing 
if __name__ == '__main__' : 
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