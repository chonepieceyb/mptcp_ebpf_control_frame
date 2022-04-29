#-*- coding:utf-8 -*-

from scapy.all import Ether, IP, raw, TCP, Raw, hexdump
from bcc import BPF, libbcc
import unittest
import ctypes as ct 
from bpf_map_def import *
from bpf_loader import *
from action_tool import *

def raw_to_pkt(raw_pkt) : 
  pkt_byte = eval(str(raw_pkt))
  return Ether(pkt_byte)

class XDPTestCase(unittest.TestCase):
    SKB_OUT_SIZE = 1514 # mtu1500 + 14 eth size

    def xdp_test_run(self, given_packet, expected_packet, expected_return):
        size = len(given_packet)

        given_packet = ct.create_string_buffer(raw(given_packet), size)
        packet_output = ct.create_string_buffer(self.SKB_OUT_SIZE)
        
        packet_output_size = ct.c_uint32()
        test_retval = ct.c_uint32()
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
            raise e 
    
    def setup(self, fd):
        self.fd = fd

def test_set_recv_win_ingress(xdp_tester):
    print("+++++test set recv win begin ++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='S', window = 100)
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='S', window = 1600)
    
    flow_actions = FlowIngressAction(local_addr = "172.16.12.128", peer_addr = "172.16.12.131")
    flow_actions.add("set_recv_win", arg_list = ["--recv_win", "1600"])
    flow_actions.submit()
    xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++test set recv win finish! ++++++++")

def test_set_flow_prio_ingress(xdp_tester):
    print("+++++test flow prio ingress 1 ++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='SA', window = 100,  options=[(30,b'\x51'),(1,b'')])
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='SA', window = 100,  options=[(30,b'\x51'),(1,b'')])

    flow_actions = FlowIngressAction(local_addr = "172.16.12.128", peer_addr = "172.16.12.131")
    flow_actions.add("set_flow_prio", backup = 1, addr_id = None)
    flow_actions.submit()
    xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++finish test flow prio ingress 1 ++++++++")

    print("+++++test flow prio ingress 2 ++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', window = 100,  options=[(30,b'\x51'),(1,b'')])
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', window = 100,  options=[(30,b'\x51'),(1,b''), (30,b'\x50\x02')])

    flow_actions = FlowIngressAction(local_addr = "172.16.12.128", peer_addr = "172.16.12.131")
    flow_actions.add("set_flow_prio", backup = 0, addr_id = 2)
    flow_actions.submit()
    xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++finish test flow prio ingress 2 ++++++++")

def test_rm_addr(xdp_tester):
    print("+++++test_rm_addr++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', options=[(30,b'\x34\x05\xdf\x03\x44\x95'),(30, b'\x20\x01\xe5\x7f\x0c\x4f')])
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', options=[(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(1,b''),(30, b'\x20\x01\xe5\x7f\x0c\x4f')])
    
    flow_actions = FlowIngressAction(local_addr = "172.16.12.128", peer_addr = "172.16.12.131")
    flow_actions.add("rm_add_addr")
    flow_actions.submit()
    xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++test_rm_addr finish! ++++++++")

def test_action_chain(xdp_tester):
    print("+++++test action chain 1(set win + set prio) ++++++++")
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', window = 100,  options=[(30,b'\x51'),(1,b'')])
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='A', window = 1600,  options=[(30,b'\x51'),(1,b''), (30,b'\x51'),(1,b'')])

    flow_actions = FlowIngressAction(local_addr = "172.16.12.128", peer_addr = "172.16.12.131")
    flow_actions.add("set_recv_win", arg_list = ["--recv_win", "1600"])
    flow_actions.add("set_flow_prio", backup = 1, addr_id = None)
    flow_actions.submit()
    xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)
    print("+++++finish test action chain 1 ++++++++")

if __name__ == '__main__': 
    xdp_main = None 
    tailcall_loader = None 
    loader = BPFObjectLoader
    with load(XDP_MAIN, loader, unpin_only_fail=False) as xdp_main:
      prog_array_fd = xdp_main.get_map_fd(XDP_ACTIONS)
      with TailCallLoader(prog_array_fd, XDP_TAIL_CALL_LIST, loader, clear_only_fail=False) as tl:
        try:
          FlowIngressAction.config()
          tester = XDPTestCase()
          tester.setup(xdp_main.get_prog_fd("xdp_main"))

          print("start test")
          
          test_set_recv_win_ingress(tester)
          test_set_flow_prio_ingress(tester)
          test_action_chain(tester)
          test_rm_addr(tester)
          print("end test")    
        except Exception as e:
          print(e)

