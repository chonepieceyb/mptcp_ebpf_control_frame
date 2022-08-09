from libbpf import * 
from scapy.all import Ether, IP, raw, TCP, hexdump
from data_struct_def import * 
from functools import *
from bpf_map_def import *
from policy_actions import RecoverAddAddr, SetFlowPrio
from utils import * 
import socket as sk 

def setup_unsock(): 
    un_sock_path = "/tmp/emptcpd.socket"
    client = sk.socket(sk.AF_UNIX, sk.SOCK_SEQPACKET)
    client.connect(un_sock_path)
    return client
    
add_addr_opt_bytes = None 
copy_pkt = None
epkt = Ether(dst='00:0c:29:29:9b:09', src='00:0c:29:f8:04:41')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 60000, flags ='A', window = 100,  options=[(30, b'\x30\x01\xac\x10\x0c\x83\xa5\x3c\x2a\xf2\x95\x20\x7e\x4d'),(30,b'\x20\x01\x0d\xa5\xa4\x76')])
client = setup_unsock()

epkt2 = Ether(dst='00:0c:29:29:9b:09', src='00:0c:29:f8:04:41')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 60000, flags ='A', window = 100, options=[(1,b''),(30,b'\x50')])

def process_recover_flow_event(data):
    print("process_recover_flow_event")
    e = ct.cast(data, ct.POINTER(mptcp_copy_pkt_event_t)).contents
    copy_pkt = SetFlowPrio.build_packet(e)
    print("--------copy_pkt-----")
    copy_pkt.show2()
    print(hexdump(raw(copy_pkt)))
    print("--------epkt-----")
    epkt2.show2()
    assert(raw(copy_pkt) == raw(epkt2))
    pkt_bytes = raw(copy_pkt)
    print("send_len %d"%len(pkt_bytes))
    client.send(pkt_bytes)

def process_rm_add_addr_event(data):
    print("process_rm_add_addr_event")
    e = ct.cast(data, ct.POINTER(rm_add_addr_event_t)).contents
    global add_addr_opt_bytes
    add_addr_opt_bytes = bytes(bytearray(e.add_addr_opt)[2:-2])

def recover_add_addr_event(data):
    print("process recover_add_addr_event")
    e = ct.cast(data, ct.POINTER(mptcp_copy_pkt_event_t)).contents
    print_hex(bytearray(e.dss_ack))
    global copy_pkt 
    copy_pkt = RecoverAddAddr.build_packet(add_addr_opt_bytes, e)
    print("--------copy_pkt-----")
    copy_pkt.show2()
    print(hexdump(raw(copy_pkt)))
    print("--------epkt-----")
    epkt.show2()
    assert(raw(copy_pkt) == raw(epkt))
    pkt_bytes = raw(copy_pkt)
    print("send_len %d"%len(pkt_bytes))
    client.send(pkt_bytes)

def process_eMPTCP_events(ctx, cpu,  data, size):
    if size < ct.sizeof(eMPTCP_event_header_t):
        return 
    e = ct.cast(data, ct.POINTER(eMPTCP_event_header_t)).contents
    event = e.event 
    print(event)
    if event == 5:
        process_rm_add_addr_event(data)
    elif event == 6:
        recover_add_addr_event(data)
    elif event == 4: 
        process_recover_flow_event(data)
    else:
        raise RuntimeError("unkonwn event :%d"%event)


if __name__ == '__main__':
    eMPTCP_events_fd = bpf_obj_get(XDP_EMPTCP_EVENTS_PATH)
    with PerfBuffer(eMPTCP_events_fd, process_eMPTCP_events) as pb:
        cnt = 0
        while True:
            try:
                pb.poll(timeout_ms = 10)
            except KeyboardInterrupt:
                break 


