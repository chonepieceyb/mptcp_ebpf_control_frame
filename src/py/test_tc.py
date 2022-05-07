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

class TCTestCase(unittest.TestCase):
    SKB_OUT_SIZE = 1514 # mtu1500 + 14 eth size

    def tc_test_run(self, given_packet, expected_packet, expected_return):
        size = len(given_packet)

        given_packet = ct.create_string_buffer(raw(given_packet), size)
        packet_output = ct.create_string_buffer(self.SKB_OUT_SIZE)
        
        packet_output_size = ct.c_uint32()
        test_retval = ct.c_int32()
        duration = ct.c_uint32()
        repeat = 1 
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
    
    def setup(self, fd):
        self.fd = fd

selector_chain = None 

def test_set_recv_win_egress(tc_tester):
    print("+++++test set recv win begin ++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='S', window = 100)
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='S', window = 1600)
    
    ac = TCEgressActionChain()
    ac.add("set_recv_win", recv_win = 1600)
    print("before add")
    policy = TCEgressPolicyChain(selector_chain, ac)
    print("before set")
    policy.set(0, remote_addr = "172.16.12.128", local_addr = "172.16.12.131")
    print("after set")
    tc_tester.tc_test_run(pkt, epkt, -1)
    print("+++++test set recv win finish! ++++++++")

def test_action_chain(tc_tester):
    print("+++++test_action_chain ++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='S', window = 100)
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='S', window = 1500)
    
    ac = TCEgressActionChain()
    ac.add("set_recv_win", recv_win = 1600).add("set_recv_win", recv_win = 1500)
    policy = TCEgressPolicyChain(selector_chain, ac)
    policy.set(0, remote_addr = "172.16.12.128", local_addr = "172.16.12.131")
    tc_tester.tc_test_run(pkt, epkt, -1)
    print("+++++test_action_chain++++++++")



def test_selector_chain(tc_tester):
    print("+++++test_selector_chain++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 1001, flags ='A', window = 100)
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(sport = 1001, flags ='A', window = 1500)

    pkt2 = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.139', dst='172.16.12.128')/TCP(sport = 1000, dport = 1000, flags ='A', window = 100)
    epkt2 = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.139', dst='172.16.12.128')/TCP(sport = 1000, dport = 1000, flags ='A', window = 1600)
    
    ac = TCEgressActionChain()
    ac.add("set_recv_win", arg_list = ["--recv_win", "1500"])
    policy = TCEgressPolicyChain(selector_chain, ac)
    policy.set(0, remote_addr = "172.16.12.128", local_addr = "172.16.12.131")

    ac2 = TCEgressActionChain()
    ac2.add("set_recv_win", arg_list = ["--recv_win", "1600"])
    policy2 = TCEgressPolicyChain(selector_chain, ac2)
    policy2.set(1)

    tc_tester.tc_test_run(pkt, epkt, -1)
    tc_tester.tc_test_run(pkt2, epkt2, -1)
    print("+++++finish test_selector_chain+++++++")


def test_catch_mptcp_option(tc_tester):
    print("+++++test_catch_option++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='223.3.71.76', dst='223.3.93.39')/TCP(sport=452, dport = 8888, flags ='S',ack = 2900, options=[('MSS',1400),(30,b'\x00\x81\x42\x64\x3e\xcb\x58\x73\xbb\xc3')])
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='223.3.71.76', dst='223.3.93.39')/TCP(sport=452, dport = 8888, flags ='S',ack = 2900, options=[('MSS',1400),(30,b'\x00\x81\x42\x64\x3e\xcb\x58\x73\xbb\xc3')])
    ac = TCEgressActionChain()
    ac.add("catch_mptcp_events")
    policy = TCEgressPolicyChain(selector_chain, ac)
    policy.set(1)
    tc_tester.tc_test_run(pkt, epkt, -1)
    print("+++++end test_catch_option++++++++")

if __name__ == '__main__': 
    loader = BPFObjectLoader
    clear_only_fail = False
    with load(TC_EGRESS_SELECTOR_ENTRY, loader, unpin_only_fail=clear_only_fail) as se, \
      load(TC_EGRESS_ACTION_ENTRY, loader, unpin_only_fail=clear_only_fail) as ae: 
      selectors_fd = se.get_map_fd(TC_EGRESS_SELECTORS)
      actions_fd = ae.get_map_fd(TC_EGRESS_ACTIONS)
      action_entry_idx = ct.c_int(ACTION_ENTRY_IDX)
      action_entry_fd = ct.c_int(ae.get_prog_fd("action_entry"))
      bpf_map_update_elem(actions_fd, ct.byref(action_entry_idx), ct.byref(action_entry_fd))
      with TailCallLoader(selectors_fd, TC_E_SELECTORS_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as stl,\
          TailCallLoader(actions_fd, TC_E_ACTIONS_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as atl:
          TCEgressSelectorChain.config()
          TCEgressPolicyChain.config()
          selector_chain = TCEgressSelectorChain()
          if not selector_chain.init: 
              print("create new subflo")
              selector_chain.add("tcp2", selector_op_type_t.SELECTOR_OR).add("tcp", selector_op_type_t.SELECTOR_AND)
              selector_chain.submit()
          tester = TCTestCase()
          tester.setup(se.get_prog_fd("selector_entry"))

          print("start test")
          try: 
            #test_set_recv_win_egress(tester)
            #test_action_chain(tester)
            #test_selector_chain(tester)
            test_catch_mptcp_option(tester)
            print("end test")    
          except Exception as e:
            print(e) 

