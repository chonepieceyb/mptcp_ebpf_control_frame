#-*- coding:utf-8 -*-

from bcc import BPF, libbcc
from scapy.all import Ether, IP, raw, TCP, Raw, hexdump

import ctypes 
import unittest
import os
import sys


TEST_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_DIR = os.path.abspath(os.path.dirname(TEST_DIR))

def raw_to_pkt(raw_pkt) : 
  pkt_byte = eval(str(raw_pkt))
  return Ether(pkt_byte)

class TCTestCase(unittest.TestCase):
    SKB_OUT_SIZE = 1514 # mtu1500 + 14 eth size

    def tc_test_run(self, given_packet, expected_packet, expected_return):
        size = len(given_packet)

        given_packet = ctypes.create_string_buffer(raw(given_packet), size)
        packet_output = ctypes.create_string_buffer(self.SKB_OUT_SIZE)
        
        packet_output_size = ctypes.c_uint32()
        test_retval = ctypes.c_uint32()
        duration = ctypes.c_uint32()
        repeat = 1 
        ret = libbcc.lib.bpf_prog_test_run(self.bpf_function.fd,
                                            repeat,
                                            ctypes.byref(given_packet),
                                            size,
                                            ctypes.byref(packet_output),
                                            ctypes.byref(packet_output_size),
                                            ctypes.byref(test_retval),
                                            ctypes.byref(duration))
        self.assertEqual(ret, 0)
        self.assertEqual(test_retval.value, expected_return)
        
        if expected_packet:
            self.assertEqual(
                packet_output[:packet_output_size.value], raw(expected_packet)
            )
       
    def setup(self, bpf_function):
        self.bpf_function = bpf_function

def test_get_mpcapble(tc_tester):
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='223.3.71.76', dst='223.3.93.39')/TCP(sport=452, dport = 8888, flags ='SA',ack = 2900, options=[('MSS',1400),(30,b'\x00\x81\x42\x64\x3e\xcb\x58\x73\xbb\xc3')])
    tc_tester.tc_test_run(pkt, None, -2)


if __name__ == '__main__' : 
    tc_path = os.path.join(TEST_DIR, "tc_ingress.c")

    bpf = BPF(src_file=tc_path, cflags=["-I%s"%TEST_DIR])
    func = bpf.load_func("tc_ingress_main", BPF.XDP)
    
    tester = TCTestCase()
    tester.setup(func)

    test_get_mpcapble(tester)