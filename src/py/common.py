#-*- coding:utf-8 -*-
import os 

#path
SRC_PY_PATH = os.path.abspath(os.path.dirname(__file__))
SRC_PATH = os.path.dirname(SRC_PY_PATH)
SRC_BPF_KERN_PATH = os.path.join(SRC_PATH, "bpf_kern")
PROJECT_ROOT_PATH = os.path.dirname(SRC_PATH)
CONFIG_PATH = os.path.join(PROJECT_ROOT_PATH, "config")
BASE_CONFIG_PATH = os.path.join(CONFIG_PATH, "base_config.yaml")

XDP_PROG_PATH = os.path.join(SRC_BPF_KERN_PATH, "xdp")
TC_PROG_PATH = os.path.join(SRC_BPF_KERN_PATH, "tc")
BPF_OBJS_PATH = os.path.join(PROJECT_ROOT_PATH, "install", "bpf_kern_objs")
BPF_TC_OBJS_PATH = os.path.join(BPF_OBJS_PATH, "tc")
BPF_TC_BTF_OBJS_PATH = os.path.join(BPF_OBJS_PATH, "tc_btf")
