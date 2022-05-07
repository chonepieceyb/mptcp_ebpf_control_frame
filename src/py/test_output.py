
#-*- coding:utf-8 -*-

from libbpf import * 
from bpf_map_def import * 
from policy_chain import * 
from utils import * 

def setup(): 
    TCEgressSelectorChain.config()
    TCEgressPolicyChain.config()
    selector_chain = TCEgressSelectorChain()
    if not selector_chain.init: 
        print("create new subflo")
        selector_chain.add("tcp", selector_op_type_t.SELECTOR_AND)
        selector_chain.submit()
    
    ac = TCEgressActionChain()
    ac.add("catch_mptcp_events")

    policy = TCEgressPolicyChain(selector_chain, ac)
    policy.set(0)

def print_tcp4_flow(flow):
    print("local_ip %s"%int2ip(int.from_bytes(val_2_bytes(flow.local_addr, 4), byteorder = "big", signed = False)))
    print("local_port %s"%int.from_bytes(val_2_bytes(flow.local_port, 2), byteorder = "big", signed = False))
    print("remote_ip %s"%int2ip(int.from_bytes(val_2_bytes(flow.remote_addr, 4), byteorder = "big", signed = False)))
    print("remote_port %s"%int.from_bytes(val_2_bytes(flow.remote_port, 2), byteorder = "big", signed = False))

def print_mp_capable(event):
    print("\nget mpcapable")
    print_tcp4_flow(event.flow)
    print("remote_key: %d"%int.from_bytes(val_2_bytes(event.remote_key, 8), byteorder = "big", signed = False))
    print("local_key: %d"%int.from_bytes(val_2_bytes(event.local_key, 8), byteorder = "big", signed = False))

def print_mp_join(event):
    print("\nget mp join")
    print_tcp4_flow(event.flow)
    print("token: %d"%int.from_bytes(val_2_bytes(event.token, 4), byteorder = "big", signed = False))

def print_fin(event):
    print("\nget fin")
    print_tcp4_flow(event.flow)

def print_mptcp_events(ctx, cpu, data, size):
    if size < ct.sizeof(eMPTCP_event_header_t):
        print("invalid events")
        return 
    
    e = ct.cast(data, ct.POINTER(eMPTCP_event_header_t)).contents
    event = e.event 
    if event == 1:
        print_mp_capable(ct.cast(data, ct.POINTER(mp_capable_event_t)).contents)
    elif event == 2:
        print_mp_join(ct.cast(data, ct.POINTER(mp_join_event_t)).contents)
    elif event == 3:
        print_fin(ct.cast(data, ct.POINTER(fin_event_t)).contents)
    else:
        print("unkonwn event :%d"%event)

if __name__ == '__main__':
    setup()
    eMPTCP_events_fd = bpf_obj_get(TC_EGRESS_EMPTCP_EVENTS_PATH)
    with PerfBuffer(eMPTCP_events_fd, print_mptcp_events) as pb:
        while True:
            try:
                pb.poll()
            except KeyboardInterrupt:
                break
          