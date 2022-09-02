#-*- coding:utf-8 -*-

from libbpf import BPF_PROG_TYPE
from common import *
from config import CONFIG
import os 
from enum import IntEnum, unique
from bpf_loader import *

#data struct 
@unique 
class Direction(IntEnum):
    INGRESS = 0,
    EGRESS = 1

#some path 

XDP_SELECTORS = "xdp_selectors"
XDP_SELECTORS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_SELECTORS)

XDP_SELECTOR_CHAIN = "xdp_selector_chain"
XDP_SELECTOR_CHAIN_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_SELECTOR_CHAIN)

XDP_ACTIONS = "xdp_actions"
XDP_ACTIONS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_ACTIONS)

XDP_ACTION_CHAINS = "xdp_action_chains"
XDP_ACTION_CHAINS_PATH =  os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_ACTION_CHAINS)

XDP_TCP2TUPLE_MAP = "xdp_tcp2tuple_map"
XDP_TCP2TUPLE_MAP_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_TCP2TUPLE_MAP)

XDP_TCP4TUPLE_MAP = "xdp_tcp4tuple_map"
XDP_TCP4TUPLE_MAP_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_TCP4TUPLE_MAP)

XDP_TCP_DEFAULT_ACTION = "xdp_tcp_default_action"
XDP_TCP_DEFAULT_ACTION_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_TCP_DEFAULT_ACTION)

XDP_DEBUG_EVENTS = 'debug_events'
XDP_DEBUG_EVENTS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_DEBUG_EVENTS)

XDP_EMPTCP_EVENTS = "xdp_eMPTCP_events"
XDP_EMPTCP_EVENTS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_EMPTCP_EVENTS)

XDP_METRICS = "xdp_metrics"
XDP_METRICS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_METRICS)

XDP_DEBUG_EVENTS_MAP = {
    "pin_path" : XDP_DEBUG_EVENTS_PATH,
    "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
}

XDP_SELECTOR_ENTRY = {
    "src_path" : os.path.join(XDP_PROG_PATH, "selector_entry.c"),
    "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "selector_entry.c.o"),
    "progs" : {
        "selector_entry" : {
            "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
        }
    },
    "pin_maps" : {
        XDP_SELECTORS : {
            "pin_path" : XDP_SELECTORS_PATH,
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        },
        XDP_SELECTOR_CHAIN: {
            "pin_path" : XDP_SELECTOR_CHAIN_PATH,
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        }
    },
    "kw": {
        "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
    }
}

#日志的事之后再说
XDP_ACTION_ENTRY = {
    "src_path" : os.path.join(XDP_PROG_PATH, "action_entry.c"),
    "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "action_entry.c.o"),
    "progs" : {
        "action_entry" : {
            "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
        }
    },
    "pin_maps" : {
        XDP_ACTIONS : {
            "pin_path" : XDP_ACTIONS_PATH,
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        },
        XDP_ACTION_CHAINS: {
            "pin_path" : XDP_ACTION_CHAINS_PATH,
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        }
    },
    "kw": {
        "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
    },
    "tail_call_map" : {
        "action_entry" : 0
    }
}

XDP_SELECTORS_TAIL_CALL_LIST = [
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "tcp2tuple_selector.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "tcp2tuple_selector.c.o"),
        "progs" : {
            "tcp2tuple_selector" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_SELECTORS : {
                "pin_path" : XDP_SELECTORS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_TCP2TUPLE_MAP : {
                "pin_path" : XDP_TCP2TUPLE_MAP_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "tcp2tuple_selector" : 1
        }
    },
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "tcp4tuple_selector.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "tcp4tuple_selector.c.o"),
        "progs" : {
            "tcp4tuple_selector" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_SELECTORS : {
                "pin_path" : XDP_SELECTORS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_TCP4TUPLE_MAP : {
                "pin_path" : XDP_TCP4TUPLE_MAP_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "tcp4tuple_selector" : 2
        }
    },
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "tcp_selector.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "tcp_selector.c.o"),
        "progs" : {
            "tcp_selector" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_SELECTORS : {
                "pin_path" : XDP_SELECTORS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_TCP_DEFAULT_ACTION : {
                "pin_path" : XDP_TCP_DEFAULT_ACTION_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "tcp_selector" : 3
        }
    }
]

XDP_ACTIONS_TAIL_CALL_LIST = [
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "set_recv_win_action.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "set_recv_win_action.c.o"),
        "progs" : {
            "set_recv_win_action" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "set_recv_win_action" : 1
        }
    },
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "set_flow_priority_action.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "set_flow_priority_action.c.o"),
        "progs" : {
            "set_flow_priority_action" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_EMPTCP_EVENTS : {
                "pin_path" : XDP_EMPTCP_EVENTS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "set_flow_priority_action" : 2
        }
    },
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "rm_add_addr_action.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "rm_add_addr_action.c.o"),
        "progs" : {
            "rm_add_addr_action" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_EMPTCP_EVENTS : {
                "pin_path" : XDP_EMPTCP_EVENTS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "rm_add_addr_action" : 3
        }
    },
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "copy_pkt_action.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "copy_pkt_action.c.o"),
        "progs" : {
            "copy_pkt_action" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_EMPTCP_EVENTS : {
                "pin_path" : XDP_EMPTCP_EVENTS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "copy_pkt_action" : 4
        }
    },
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "record_action.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "record_action.c.o"),
        "progs" : {
            "record_action" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_METRICS : {
                "pin_path" : XDP_METRICS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "record_action" : 5
        }
    }
]

def xdp_set_debug():
    XDP_SELECTOR_ENTRY["pin_maps"][XDP_DEBUG_EVENTS] = XDP_DEBUG_EVENTS_MAP
    XDP_ACTION_ENTRY["pin_maps"][XDP_DEBUG_EVENTS] = XDP_DEBUG_EVENTS_MAP
    for v in XDP_ACTIONS_TAIL_CALL_LIST:
        v["pin_maps"][XDP_DEBUG_EVENTS] = XDP_DEBUG_EVENTS_MAP
    for v in XDP_SELECTORS_TAIL_CALL_LIST:
        v["pin_maps"][XDP_DEBUG_EVENTS] = XDP_DEBUG_EVENTS_MAP

XDP_SELECTOR_NAME_IDX_MAP = get_name_idx_map(XDP_SELECTORS_TAIL_CALL_LIST)
XDP_SELECTOR_IDX_NAME_MAP = get_idx_name_map(XDP_SELECTORS_TAIL_CALL_LIST)
XDP_ACTION_NAME_IDX_MAP = get_name_idx_map(XDP_ACTIONS_TAIL_CALL_LIST)
XDP_ACTION_IDX_NAME_MAP = get_idx_name_map(XDP_ACTIONS_TAIL_CALL_LIST)

TC_EGRESS_EMPTCP_EVENTS = "tc_egress_eMPTCP_events"
TC_EGRESS_EMPTCP_EVENTS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, TC_EGRESS_EMPTCP_EVENTS)

TC_EGRESS_SELECTORS = "tc_egress_selectors"
TC_EGRESS_SELECTORS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, TC_EGRESS_SELECTORS)

TC_EGRESS_SELECTOR_CHAIN = "tc_egress_selector_chain"
TC_EGRESS_SELECTOR_CHAIN_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, TC_EGRESS_SELECTOR_CHAIN)

TC_EGRESS_ACTIONS = "tc_egress_actions"
TC_EGRESS_ACTIONS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, TC_EGRESS_ACTIONS)

TC_EGRESS_ACTION_CHAINS = "tc_egress_action_chains"
TC_EGRESS_ACTION_CHAINS_PATH =  os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, TC_EGRESS_ACTION_CHAINS)

TC_EGRESS_TCP2TUPLE_MAP = "tc_egress_tcp2tuple_map"
TC_EGRESS_TCP2TUPLE_MAP_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, TC_EGRESS_TCP2TUPLE_MAP)

TC_EGRESS_TCP_DEFAULT_ACTION = "tc_egress_tcp_default_action"
TC_EGRESS_TCP_DEFAULT_ACTION_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, TC_EGRESS_TCP_DEFAULT_ACTION)

#TC program 
TC_EGRESS_SELECTOR_ENTRY = {
    "src_path" : os.path.join(TC_EGRESS_PROG_PATH, "selector_entry.c"),
    "obj_path" : os.path.join(BPF_TC_EGRESS_OBJS_PATH, "selector_entry.c.o"),
    "progs" : {
        "selector_entry" : {
            "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_SCHED_CLS
        }
    },
    "pin_maps" : {
        TC_EGRESS_SELECTORS : {
            "pin_path" : TC_EGRESS_SELECTORS_PATH,
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        },
        TC_EGRESS_SELECTOR_CHAIN: {
            "pin_path" : TC_EGRESS_SELECTOR_CHAIN_PATH,
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        }
    },
    "kw": {
        "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
    }
}

TC_EGRESS_ACTION_ENTRY = {
    "src_path" : os.path.join(TC_EGRESS_PROG_PATH, "action_entry.c"),
    "obj_path" : os.path.join(BPF_TC_EGRESS_OBJS_PATH, "action_entry.c.o"),
    "progs" : {
        "action_entry" : {
            "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_SCHED_CLS
        }
    },
    "pin_maps" : {
        TC_EGRESS_ACTIONS : {
            "pin_path" : TC_EGRESS_ACTIONS_PATH,
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        },
        TC_EGRESS_ACTION_CHAINS: {
            "pin_path" : TC_EGRESS_ACTION_CHAINS_PATH,
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        }
    },
    "kw": {
        "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
    },
    "tail_call_map" : {
        "action_entry" : 0
    }
}

TC_E_SELECTORS_TAIL_CALL_LIST = [
    {
        "src_path" : os.path.join(TC_EGRESS_PROG_PATH, "tcp2tuple_selector.c"),
        "obj_path" : os.path.join(BPF_TC_EGRESS_OBJS_PATH, "tcp2tuple_selector.c.o"),
        "progs" : {
            "tcp2tuple_selector" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_SCHED_CLS
            }
        },
        "pin_maps" : {
            TC_EGRESS_SELECTORS : {
                "pin_path" : TC_EGRESS_SELECTORS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            TC_EGRESS_ACTIONS : {
                "pin_path" : TC_EGRESS_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            TC_EGRESS_TCP2TUPLE_MAP : {
                "pin_path" : TC_EGRESS_TCP2TUPLE_MAP_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "tcp2tuple_selector" : 1
        }
    },
    {
        "src_path" : os.path.join(TC_EGRESS_PROG_PATH, "tcp_selector.c"),
        "obj_path" : os.path.join(BPF_TC_EGRESS_OBJS_PATH, "tcp_selector.c.o"),
        "progs" : {
            "tcp_selector" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_SCHED_CLS
            }
        },
        "pin_maps" : {
            TC_EGRESS_SELECTORS : {
                "pin_path" : TC_EGRESS_SELECTORS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            TC_EGRESS_ACTIONS : {
                "pin_path" : TC_EGRESS_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            TC_EGRESS_TCP_DEFAULT_ACTION : {
                "pin_path" : TC_EGRESS_TCP_DEFAULT_ACTION_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "tcp_selector" : 2
        }
    }
]

TC_E_ACTIONS_TAIL_CALL_LIST = [ 
    {
        "src_path" : os.path.join(TC_EGRESS_PROG_PATH, "set_recv_win_action.c"),
        "obj_path" : os.path.join(BPF_TC_EGRESS_OBJS_PATH, "set_recv_win_action.c.o"),
        "progs" : {
            "set_recv_win_action" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_SCHED_CLS
            }
        },
        "pin_maps" : {
            TC_EGRESS_ACTIONS : {
                "pin_path" : TC_EGRESS_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "set_recv_win_action" : 1
        }
    },
    {
        "src_path" : os.path.join(TC_EGRESS_PROG_PATH, "catch_mptcp_events_action.c"),
        "obj_path" : os.path.join(BPF_TC_EGRESS_OBJS_PATH, "catch_mptcp_events_action.c.o"),
        "progs" : {
            "catch_mptcp_events_action" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_SCHED_CLS
            }
        },
        "pin_maps" : {
            TC_EGRESS_ACTIONS : {
                "pin_path" : TC_EGRESS_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            TC_EGRESS_EMPTCP_EVENTS: {
                "pin_path" : TC_EGRESS_EMPTCP_EVENTS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "catch_mptcp_events_action" : 2
        }
    },
    {
        "src_path" : os.path.join(TC_EGRESS_PROG_PATH, "set_flow_priority_action.c"),
        "obj_path" : os.path.join(BPF_TC_EGRESS_OBJS_PATH, "set_flow_priority_action.c.o"),
        "progs" : {
            "set_flow_priority_action" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_SCHED_CLS
            }
        },
        "pin_maps" : {
            TC_EGRESS_ACTIONS : {
                "pin_path" : TC_EGRESS_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "set_flow_priority_action" : 3
        }
    },
    {
        "src_path" : os.path.join(TC_EGRESS_PROG_PATH, "rm_add_addr_action.c"),
        "obj_path" : os.path.join(BPF_TC_EGRESS_OBJS_PATH, "rm_add_addr_action.c.o"),
        "progs" : {
            "rm_add_addr_action" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_SCHED_CLS
            }
        },
        "pin_maps" : {
            TC_EGRESS_ACTIONS : {
                "pin_path" : TC_EGRESS_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "rm_add_addr_action" : 4
        }
    }
]

TC_E_SELECTOR_NAME_IDX_MAP = get_name_idx_map(TC_E_SELECTORS_TAIL_CALL_LIST)
TC_E_SELECTOR_IDX_NAME_MAP = get_idx_name_map(TC_E_SELECTORS_TAIL_CALL_LIST)
TC_E_ACTION_NAME_IDX_MAP = get_name_idx_map(TC_E_ACTIONS_TAIL_CALL_LIST)
TC_E_ACTION_IDX_NAME_MAP = get_idx_name_map(TC_E_ACTIONS_TAIL_CALL_LIST)

ACTION_ENTRY_IDX = 0

# test program 
if __name__ == '__main__': 
    from socket import if_nametoindex
    import ctypes as ct 
    from libbpf import *
    import sys 
    cmd = int(sys.argv[1])

    loader = BPFObjectLoader
    clear_only_fail = True 
    '''
        with load(XDP_SELECTOR_ENTRY, loader, unpin_only_fail=clear_only_fail) as se, \
            load(XDP_ACTION_ENTRY, loader, unpin_only_fail=clear_only_fail) as ae: 
            xdp_selectors_fd = se.get_map_fd(XDP_SELECTORS)
            xdp_actions_fd = ae.get_map_fd(XDP_ACTIONS)
            action_entry_idx = ct.c_int(ACTION_ENTRY_IDX)
            action_entry_fd = ct.c_int(ae.get_prog_fd("action_entry"))
            bpf_map_update_elem( xdp_actions_fd, ct.byref(action_entry_idx), ct.byref(action_entry_fd))
            with TailCallLoader(xdp_selectors_fd, XDP_SELECTORS_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as stl,\
                TailCallLoader(xdp_actions_fd, XDP_ACTIONS_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as atl:
                pass 

        with load(TC_EGRESS_SELECTOR_ENTRY, loader ,unpin_only_fail=clear_only_fail) as se,\
            load(TC_EGRESS_ACTION_ENTRY, loader ,unpin_only_fail=clear_only_fail) as ae:
            tc_egress_selectors_fd = se.get_map_fd(TC_EGRESS_SELECTORS)
            tc_egress_actions_fd = ae.get_map_fd(TC_EGRESS_ACTIONS)
            action_entry_idx = ct.c_int(ACTION_ENTRY_IDX)
            action_entry_fd = ct.c_int(ae.get_prog_fd("action_entry"))
            bpf_map_update_elem(tc_egress_actions_fd, ct.byref(action_entry_idx), ct.byref(action_entry_fd))
            with TailCallLoader(tc_egress_selectors_fd, TC_E_SELECTORS_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as stl, \
                TailCallLoader(tc_egress_actions_fd, TC_E_ACTIONS_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as atl:
                pass
    '''
    af_xdp_kern = {
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "af_xdp_kern.c.o"),
        "progs" : {
            "xdp_sock_prog" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            "xsks_map" : {
                "pin_path": "/sys/fs/bpf/xsks_map",
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
    }
    if cmd == 0 :
        with load(af_xdp_kern, loader, unpin_only_fail=clear_only_fail) as af:
            bpf_xdp_attach(if_nametoindex("ens34"), af.get_prog_fd("xdp_sock_prog"), XDP_FLAGS.XDP_FLAGS_UPDATE_IF_NOEXIST, ct.c_void_p(None))
            print("load success")
    else:
        fd = bpf_obj_get("/sys/fs/bpf/xsks_map")
        key = ct.c_int(0)
        value = ct.c_int(int(cmd))
        bpf_map_update_elem(fd,ct.byref(key), ct.byref(value))
