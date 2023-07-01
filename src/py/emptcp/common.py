#-*- coding:utf-8 -*-
import os 

#path
SRC_PY_PATH = os.path.abspath(os.path.dirname(__file__))
SRC_PATH = os.path.dirname(os.path.dirname(SRC_PY_PATH))
SRC_BPF_KERN_PATH = os.path.join(SRC_PATH, "bpf_kern")
PROJECT_ROOT_PATH = os.path.dirname(SRC_PATH)
CONFIG_PATH = os.path.join(PROJECT_ROOT_PATH, "config")
BASE_CONFIG_PATH = os.path.join(CONFIG_PATH, "base_config.yaml")

XDP_PROG_PATH = os.path.join(SRC_BPF_KERN_PATH, "xdp")
TC_EGRESS_PROG_PATH = os.path.join(SRC_BPF_KERN_PATH, "tc_egress")
BPF_OBJS_PATH = os.path.join(PROJECT_ROOT_PATH, "install", "bpf_kern_objs")
BPF_TC_EGRESS_OBJS_PATH = os.path.join(BPF_OBJS_PATH, "tc_egress")
BPF_XDP_OBJS_PATH = os.path.join(BPF_OBJS_PATH, "xdp")
BPF_KPROBE_OBJS_PATH = os.path.join(BPF_OBJS_PATH, "kprobe")
BPF_STOPS_OBJS_PATH = os.path.join(BPF_OBJS_PATH, "struct_ops")

BPF_VFS_PREFIX = "/sys/fs/bpf"
LINUX_SRC_DIR = os.path.join(PROJECT_ROOT_PATH, "linux")
LIBBPF_SO_PATH = os.path.join(LINUX_SRC_DIR, 'tools', 'lib', 'bpf', 'libbpf.so')