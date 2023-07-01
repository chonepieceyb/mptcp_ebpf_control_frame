from libbpf import * 

class BPFObject:
    def __init__(self, obj_path):
        self.is_loaded = False
        self.obj_path = obj_path
        self.obj = None
        
    def __enter__(self):
        self.obj = bpf_object__open(self.obj_path)
        return self 
    
    def __del__(self):
        if self.obj != None: 
            bpf_object__close(self.obj)
        
    def __exit__(self, type, value, trace):
        if type != None: 
            print("type:", type)
            print("value:", value)
            print("trace:", trace)
        if self.obj != None: 
            bpf_object__close(self.obj)
            self.obj = None
    
    def transfer(self):
        other_obj = BPFObject(self.obj_path)
        other_obj.obj = self.obj
        other_obj.obj_path = self.obj_path
        other_obj.is_loaded = self.is_loaded
        self.obj = None 
        self.is_loaded = False 
        return other_obj
    
    def load(self):
        assert self.obj != None and (not self.is_loaded) and "can't not load empty obj or loaded obj"
        bpf_object__load(self.obj)
        self.is_loaded = True
    
    def get_prog(self, name):
        return bpf_object__find_program_by_name(self.obj, name)
    
    def get_map(self, name):
        return bpf_object__find_map_by_name(self.obj, name)

class BPFLink:
    def __init__(self, attach_func, *args):
        #attach_func should raise an libbpf_error in erro and return an object of bpf_link
        self.link = None 
        self.attach_func = attach_func 
        self.args = args 
        
    def __enter__(self):
        self.link = self.attach_func(*(self.args))
        return self 

    def pin(self, path):
        bpf_link__pin(self.link, path)
        
    def disconnect(self):
        bpf_link__disconnect(self.link)
    
    def __exit__(self, type, value, trace):
        if type != None: 
            print("type:", type)
            print("value:", value)
            print("trace:", trace)
        if self.link != None:
            try: 
                bpf_link__destroy(self.link)
            except Exception as e:
                print(e)

#Map oprations without fd (resources)
class BPFMapView:
    def __init__(self, bpf_map):
        self.map = bpf_map 
    
    def set_extra(self, map_extra):
        bpf_map__set_map_extra(self.map, map_extra)  

    def set_cmap_id(self, cmap_id):
        self.set_extra(cmap_id << 32)
        
#Map oprations with fd (resources)
class BPFMap(BPFMapView):
    def __init__(self, bpf_map, key_type, value_type):
        super().__init__(bpf_map)
        assert key_type != None and value_type != None
        self.fd = bpf_map__fd(self.map)
        self.key_type = key_type
        self.value_type = value_type
    
    def lookup(self, key):
        '''
        @key : key to lookup , ctypes
        return value
        '''
        assert self.key_type != None and self.value_type != None and isinstance(key, self.key_type)
        value = self.value_type()
        bpf_map_lookup_elem(self.fd, ct.byref(key), ct.byref(value))
        return value
    
    def update(self, key, value, flags):
        assert self.key_type != None and self.value_type != None and isinstance(key, self.key_type) and isinstance(value, self.value_type)
        bpf_map_update_elem(self.fd, ct.byref(key), ct.byref(value), flags)
        
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


def init_bpf_opts(opt_type):
    opt = opt_type()
    memset(opt, 0)
    if hasattr(opt, "sz"):
        setattr(opt, "sz", ct.sizeof(opt))
    return opt

def create_bpf_opts(opt_type, **kw):
    opt = init_bpf_opts(opt_type)
    for key, value in kw.items():
        setattr(opt, key, value)
    return opt

def to_void_p(obj):
    return ct.cast(ct.byref(obj), ct.c_void_p)

def detach_struct_ops(obj, map_name):
    key = ct.c_int(0)
    bpf_map_delete_elem(bpf_map__fd(obj.get_map(map_name)), ct.byref(key))