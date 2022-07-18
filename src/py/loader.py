from bpf_loader import *
from libbpf import *
from socket import if_nametoindex
from bpf_map_def import *

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
        # for obj in TC_E_SELECTORS_TAIL_CALL_LIST:
            # unpin_obj(obj)
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
#    tool.attach()
   tool.detach()