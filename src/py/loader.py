from bpf_loader import *
from libbpf import *
from socket import if_nametoindex
from bpf_map_def import *

TC_EGRESS_ACTION_SET = {
    "src_path" : os.path.join(TC_EGRESS_PROG_PATH, "hit_buffer.c"),
    "obj_path" : os.path.join(BPF_TC_EGRESS_OBJS_PATH, "hit_buffer.c.o"),
    "progs" : {
        "hit_buffer" : {
            "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_SCHED_CLS
        }
    },
    "pin_maps" : {
        "check_hit": {
            "pin_path" : "/sys/fs/bpf/eMPTCP/check_hit",
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        }
    },
    "kw": {
        "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
    }
}

# TC_E_BUFFER_TAIL_CALL_LIST = [
#     {
#         "src_path" : os.path.join(TC_EGRESS_PROG_PATH, "hit_buffer_syn.c"),
#         "obj_path" : os.path.join(BPF_TC_EGRESS_OBJS_PATH, "hit_buffer_syn.c.o"),
#         "progs" : {
#             "hit_buffer_syn" : {
#                 "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_SCHED_CLS
#             }
#         },
#         "pin_maps" : {
#             "check_hit" : {
#                 "pin_path" : "/sys/fs/bpf/eMPTCP/check_hit",
#                 "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
#             },
#             "check_fin" : {
#                 "pin_path" : "/sys/fs/bpf/eMPTCP/check_fin",
#                 "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
#             }
#         },
#         "kw": {
#             "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
#         },
#         "tail_call_map" : {
#             "hit_buffer_syn" : 0
#         }
#     }
# ]


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
        with load(TC_EGRESS_ACTION_SET, self.loader) as ae:
            # with TailCallLoader(ae.get_map_fd("hit_buffer_submap"), TC_E_BUFFER_TAIL_CALL_LIST, self.loader) as stl:
            for interface in self.interfaces:
                print("atttach tc ingress to %s"%interface)
                ifindex = if_nametoindex(interface)
                egress_hook = init_libbpf_opt(bpf_tc_hook, ifindex = ifindex, attach_point = BPF_TC_ATTACH_POINT.BPF_TC_INGRESS)
                opts = init_libbpf_opt(bpf_tc_opts, prog_fd = ae.get_prog_fd("hit_buffer"))
                bpf_tc_attach(egress_hook, opts)


    def detach(self):
        self._destroy_hooks()
        # unpin_obj(TC_EGRESS_SELECTOR_ENTRY)
        unpin_obj(TC_EGRESS_ACTION_SET)
        # for obj in TC_E_BUFFER_TAIL_CALL_LIST:
        #     unpin_obj(obj)
        # for obj in TC_E_ACTIONS_TAIL_CALL_LIST:
            # unpin_obj(obj)
    
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

if __name__ == '__main__' :
   tool = TCEgressProgLoader(["ens33","ens38"], BPFObjectLoader)
   tool.detach()
   tool.attach()
