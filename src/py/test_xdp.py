#-*- coding:utf-8 -*-

from scapy.all import Ether, IP, raw, TCP, hexdump
from bcc import BPF, libbcc
import unittest
import ctypes as ct 
from bpf_map_def import *
from bpf_loader import *
from policy_chain import *

def raw_to_pkt(raw_pkt) : 
  pkt_byte = eval(str(raw_pkt))
  return Ether(pkt_byte)

class XDPTestCase(unittest.TestCase):
    SKB_OUT_SIZE = 1514 # mtu1500 + 14 eth size

    def xdp_test_run(self, given_packet, expected_packet, expected_return, repeat = 1):
        size = len(given_packet)

        given_packet = ct.create_string_buffer(raw(given_packet), size)
        packet_output = ct.create_string_buffer(self.SKB_OUT_SIZE)
        
        packet_output_size = ct.c_uint32()
        test_retval = ct.c_uint32()
        duration = ct.c_uint32()
        ret = libbcc.lib.bpf_prog_test_run(self.fd,
                                            repeat,
                                            ct.byref(given_packet),
                                            size,
                                            ct.byref(packet_output),
                                            ct.byref(packet_output_size),
                                            ct.byref(test_retval),
                                            ct.byref(duration))
        self.assertEqual(ret, 0)
        self.assertEqual(test_retval.value, expected_return)
        
        try:
          if expected_packet:
            self.assertEqual(
              packet_output[:packet_output_size.value], raw(expected_packet)
            )
        except Exception as e:
            print("+++++out packet+++++")
            print(bytes(packet_output[:packet_output_size.value]))
            output_pkt = raw_to_pkt(packet_output[:packet_output_size.value])
            output_pkt.show2()
            hexdump(output_pkt)
            print("++++recompute csum+++")
            tcphdr = output_pkt[TCP]
            del tcphdr.chksum
            tcphdr.show2()
            print("++++expected output+++")
            expected_packet.show2()
            hexdump(expected_packet)
            raise(e)
        return duration.value 

    def setup(self, fd):
        self.fd = fd

selector_chain = None 

def test_set_recv_win_ingress(sc, xdp_tester):
    print("+++++test xdp set recv win begin ++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='S', window = 100)
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='S', window = 1600)
    
    ac = XDPActionChain()
    ac.add("set_recv_win", recv_win = 1600)
    policy = XDPPolicyChain(sc, ac)
    policy.set(1, local_addr = "172.16.12.128", remote_addr = "172.16.12.131")
    duration = xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++test set recv win finish! ++++++++")
    return duration 

def test_set_flow_prio_ingress1(sc, xdp_tester):
    print("+++++test flow prio ingress 1 ++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='SA', window = 100,  options=[(30,b'\x51'),(1,b'')])
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='SA', window = 100,  options=[(30,b'\x51'),(1,b'')])
    
    ac = XDPActionChain()
    ac.add("set_flow_prio", backup = 1, addr_id = None)
    policy = XDPPolicyChain(sc, ac)
    policy.set(1, local_addr = "172.16.12.128", remote_addr = "172.16.12.131")
    duration = xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++finish test flow prio ingress 1 ++++++++")
    return duration 

def test_set_flow_prio_ingress2(sc, xdp_tester):
    print("+++++test flow prio ingress 2 ++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', window = 100,  options=[(30,b'\x51'),(1,b'')])
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', window = 100,  options=[(30,b'\x51'),(1,b''), (30,b'\x50\x02')])
    
    ac = XDPActionChain()
    ac.add("set_flow_prio", backup = 0, addr_id = 2)
    policy = XDPPolicyChain(sc, ac)
    policy.set(1, local_addr = "172.16.12.128", remote_addr = "172.16.12.131")
    duration = xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++finish test flow prio ingress 2 ++++++++")
    return duration

def test_rm_addr(sc, xdp_tester):
    print("+++++test_rm_addr++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', options=[(30,b'\x34\x05\xdf\x03\x44\x95'),(30, b'\x20\x01\xe5\x7f\x0c\x4f')])
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', options=[(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(30, b'\x20\x01\xe5\x7f\x0c\x4f')])
    ac = XDPActionChain()
    ac.add("rm_add_addr")
    policy = XDPPolicyChain(sc, ac)
    policy.set(1, local_addr = "172.16.12.128", remote_addr = "172.16.12.131")
    duration = xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++test_rm_addr finish! ++++++++")
    return duration 

def test_action_chain(sc, xdp_tester):
    print("+++++test action chain 1(set win + set prio) ++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', window = 100,  options=[(30,b'\x51'),(1,b'')])
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', window = 1600,  options=[(30,b'\x51'),(1,b''), (30,b'\x51'),(1,b'')])
    ac = XDPActionChain()
    ac.add("set_recv_win", arg_list = ["--recv_win", "1600"]).add("set_flow_prio", backup = 1, addr_id = None)
    policy = XDPPolicyChain(sc, ac)
    policy.set(1, local_addr = "172.16.12.128", remote_addr = "172.16.12.131")
    xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
      
    print("+++++finish test action chain 1 ++++++++")

def test_selector_chain(sc, xdp_tester):
    print("+++++test_selector_chain++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 1001, flags ='A', window = 100,  options=[(30,b'\x51'),(1,b'')])
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 1001, flags ='A', window = 100,  options=[(30,b'\x51'),(1,b''), (30,b'\x51'),(1,b'')])

    pkt2 = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 1000, dport = 1000, flags ='A', window = 100)
    epkt2 = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 1000, dport = 1000, flags ='A', window = 1600)
    
    pkt3 = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.2', dst='172.16.12.3')/TCP(sport = 1000, dport = 1000, flags ='A', window = 100)
    epkt3  = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.2', dst='172.16.12.3')/TCP(sport = 1000, dport = 1000, flags ='A', window = 65535)
    
    ac = XDPActionChain()
    ac.add("set_flow_prio", backup = 1, addr_id = None)
    policy = XDPPolicyChain(sc, ac)
    policy.set(1, local_addr = "172.16.12.128", remote_addr = "172.16.12.131")

    ac2 = XDPActionChain()
    ac2.add("set_recv_win", arg_list = ["--recv_win", "1600"])
    policy2 = XDPPolicyChain(sc, ac2)
    policy2.set(0, local_addr = "172.16.12.128", remote_addr = "172.16.12.131", local_port = 1000, remote_port = 1000)
    
    ac3 = XDPActionChain()
    ac3.add("set_recv_win", arg_list = ["--recv_win", "65535"])
    policy3= XDPPolicyChain(sc, ac3)
    policy3.set(2)

    xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    xdp_tester.xdp_test_run(pkt2, epkt2, BPF.XDP_PASS)
    xdp_tester.xdp_test_run(pkt3, epkt3, BPF.XDP_PASS)
    print("+++++finish test_selector_chain+++++++")

def test_rm_add_addr_v1(sc, xdp_tester):
    print("+++++test rm add addr v1++++++++")
    #pkt = Ether(dst='00:0c:29:29:9b:09', src='00:0c:29:f8:04:41')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 60000, flags ='A', window = 100,  options=[(30, b'\x30\x01\xac\x10\x0c\x83\xa5\x3c\x2a\xf2\x95\x20\x7e\x4d'),(30,b'\x20\x01\x0d\xa5\xa4\x76')])
    #epkt = Ether(dst='00:0c:29:29:9b:09', src='00:0c:29:f8:04:41')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 60000, flags ='A', window = 100, options=[(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(30,b'\x20\x01\x0d\xa5\xa4\x76')])
    pkt = Ether(dst='00:0c:29:29:9b:09', src='00:0c:29:f8:04:41')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 60000, flags ='A', window = 100,  options=[(30, b'\x30\x01\xac\x10\x0c\x83\xa5\x3c\x2a\xf2\x95\x20\x7e\x4d')])
    epkt = Ether(dst='00:0c:29:29:9b:09', src='00:0c:29:f8:04:41')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 60000, flags ='A', window = 100, options=[(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b'')])
   
    ac = XDPActionChain()
    ac.add("rm_add_addr")
    #ac.add("recover_add_addr")
    ac.add("recover_add_addr")
    policy = XDPPolicyChain(sc, ac)
    policy.set(1, local_addr = "172.16.12.128", remote_addr = "172.16.12.131")
    #xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
   
    xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++end test rm add addr v1++++++++")

def test_recover_flow(sc, xdp_tester):
    print("+++++test recover flow++++++++")
    #pkt = Ether(dst='00:0c:29:29:9b:09', src='00:0c:29:f8:04:41')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 60000, flags ='A', window = 100,  options=[(30, b'\x30\x01\xac\x10\x0c\x83\xa5\x3c\x2a\xf2\x95\x20\x7e\x4d'),(30,b'\x20\x01\x0d\xa5\xa4\x76')])
    #epkt = Ether(dst='00:0c:29:29:9b:09', src='00:0c:29:f8:04:41')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 60000, flags ='A', window = 100, options=[(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(30,b'\x20\x01\x0d\xa5\xa4\x76')])
    pkt = Ether(dst='00:0c:29:29:9b:09', src='00:0c:29:f8:04:41')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 60000, flags ='A', window = 100,  options=[])
    epkt = Ether(dst='00:0c:29:29:9b:09', src='00:0c:29:f8:04:41')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 60000, flags ='A', window = 100, options=[(30,b'\x51'),(1,b'')])
   
    ac = XDPActionChain()
    ac.add("set_flow_prio", backup = 1, addr_id = None)
    #ac.add("recover_add_addr")
    ac.add("recover_add_addr")
    policy = XDPPolicyChain(sc, ac)
    policy.set(1, local_addr = "172.16.12.128", remote_addr = "172.16.12.131")
    #xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
   
    xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++end test rm add addr v1++++++++")

if __name__ == '__main__': 
    #xdp_set_debug()
    loader = BPFObjectLoader
    clear_only_fail = False
    with load(XDP_SELECTOR_ENTRY, loader, unpin_only_fail=clear_only_fail) as xdp_selector_entry, \
      load(XDP_ACTION_ENTRY, loader, unpin_only_fail=clear_only_fail) as xdp_action_entry: 
      xdp_selectors_fd = xdp_selector_entry.get_map_fd(XDP_SELECTORS)
      xdp_actions_fd = xdp_action_entry.get_map_fd(XDP_ACTIONS)
      action_entry_idx = ct.c_int(ACTION_ENTRY_IDX)
      action_entry_fd = ct.c_int(xdp_action_entry.get_prog_fd("action_entry"))
      bpf_map_update_elem( xdp_actions_fd, ct.byref(action_entry_idx), ct.byref(action_entry_fd))
      with TailCallLoader(xdp_selectors_fd, XDP_SELECTORS_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as stl,\
          TailCallLoader(xdp_actions_fd, XDP_ACTIONS_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as atl: 
          XDPSelectorChain.config()
          XDPPolicyChain.config()
          selector_chain = XDPSelectorChain()
          selector_chain.add("tcp4", selector_op_type_t.SELECTOR_OR).add("tcp2", selector_op_type_t.SELECTOR_OR).add("tcp", selector_op_type_t.SELECTOR_AND)
          selector_chain.submit()
          tester = XDPTestCase()
          tester.setup(xdp_selector_entry.get_prog_fd("selector_entry"))

          print("start test")
          try: 
            #test_set_recv_win_ingress(selector_chain, tester)
            #test_set_flow_prio_ingress1(selector_chain,tester)
            #test_set_flow_prio_ingress2(selector_chain,tester)
            #test_action_chain(selector_chain,tester)
            #test_rm_addr(selector_chain,tester)
            #test_selector_chain(selector_chain, tester)
            #test_rm_add_addr_v1(selector_chain, tester)
            test_recover_flow(selector_chain, tester)
            print("end test")  
            pass   
          except Exception as e:
            print(e) 

