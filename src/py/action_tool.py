#-*- coding:utf-8 -*-
from actions import * 
from config import CONFIG
from utils import *
from socket import inet_aton
from libbpf import *
from bpf_map_def import SUBFLOW_ACTION_INGRESS

ACTION_DICT = {
    "set_recv_win_in" : SetRecvWinIngress
}

def flow_action_parse_args(arg_list):
    parser = argparse.ArgumentParser(description="init flow actions")
    parser.add_argument("--local_addr", type = str, required=True, help = "local_ip")
    parser.add_argument("--peer_addr", type = str, required=True, help = "peer_ip")
    args = parser.parse_args(args = arg_list)
    return vars(args)

class FlowIngressAction:
    
    @classmethod
    def print_raw_action(cls, a):
        action_str = """param_type: %d
action: %d %s"""

        if a.param_type == param_type_t.IMME:
            param_str = """
imme : %d"""%a.u2.imme 
        else:
            param_str = """
offset:%d
version:%d"""%(a.u2.offset, a.u2.version)
        return action_str%(a.param_type, a.u1.action, param_str)

    @ArgWrapper(flow_action_parse_args)
    def __init__(self, *, local_addr, peer_addr):
        self.subflow_actions_fd = bpf_obj_get(SUBFLOW_ACTION_INGRESS_PATH)
        self.local_addr = local_addr.strip('"')
        self.peer_addr = peer_addr.strip('"')
        #self.local_addr = "127.0.0.1"
        #self.peer_addr = "127.0.0.1"
        self.flow_key = flow_key_t()
        setzero(self.flow_key)
        self.flow_key.local_addr = bytes_2_val(inet_aton(self.local_addr))
        self.flow_key.peer_addr =  bytes_2_val(inet_aton(self.peer_addr))
        self.subflow_actions = xdp_action_value_t()
        setzero(self.subflow_actions)
        self.action_count = 0
        self.action_objs = []

    def add(self, name, arg_list):
        if self.action_count >= CONFIG.subflow_max_action_num:
            raise RuntimeError("fail to add action : too much action, max_action_num :%d"%CONFIG.subflow_max_action_num)
        action_obj = ACTION_DICT[name](arg_list = arg_list)
        self.action_objs.append(action_obj)
        action_dump, _ = action_obj.dump()
        self.subflow_actions.actions[self.action_count] = action_dump 
        self.action_count += 1

    def submit(self):
        self.print_subflow_action()
        bpf_map_update_elem(self.subflow_actions_fd, ct.byref(self.flow_key), ct.byref(self.subflow_actions))

    def print_subflow_action(self, print_human = True): 
        print("version: %d"%self.subflow_actions.version)
        for i in range(self.action_count):
            a = self.subflow_actions.actions[i]
            print(FlowIngressAction.print_raw_action(a),end = "")
            if print_human: 
                print()
                print(self.action_objs[i].print(), end = "")
            print()

    def print_flow_info(self):
        return "local_addr: %s, peer_addr %s"%(self.local_addr, self.peer_addr)

def cmd_show_argparser(arg_list):
    parser = argparse.ArgumentParser(description="show keeping flow info", prog = "show")
    # add egress future 
    parser.add_argument(dest = "direction", type = str, choices=["ingress"], help = "flow direction, ingress/egress")
    args  = parser.parse_args(arg_list)
    return vars(args)

def cmd_create_argparser(arg_list):
    parser = argparse.ArgumentParser(description="create flow action", prog = "create")
    parser.add_argument(dest = "direction", type = str, choices=["ingress"], help = "flow direction, ingress/egress")
    args , res_args = parser.parse_known_args(arg_list)
    return vars(args), res_args 


def cmd_add_argparser(arg_list):
    parser = argparse.ArgumentParser(description="add action", prog = "add")
    parser.add_argument("-i", "--index", type = int, required=True, help = "flow index")
    parser.add_argument(dest = "direction", type = str, choices=["ingress"], help = "flow direction, ingress/egress")
    parser.add_argument(dest = "action_name", type = str, help = "action name")
    args , res_args = parser.parse_known_args(arg_list)
    return vars(args), res_args 

def cmd_submit_argparser(arg_list):
    parser = argparse.ArgumentParser(description="add action", prog = "submit")
    parser.add_argument("-i", "--index", type = int, required=True, help = "flow index")
    parser.add_argument(dest = "direction", type = str, choices=["ingress"], help = "flow direction, ingress/egress")
    args = parser.parse_args(arg_list)
    return vars(args)

class Tool:
    def __init__(self) -> None:
        self.ingress_flow_actions = []
        self.cmd_dict = {
            "show" : {
                "func" : self._cmd_show,
                "desc" : "show flow info"
            },
            "create" : {
                "func" : self._cmd_create,
                "desc" : "create new subflow action"
            },
            "add" : {
                "func" : self._cmd_add,
                "desc" : "add action to flow"
            },
            "submit" : {
                "func" : self._cmd_submit,
                "desc" : "submit action"
            },
        }

    def run(self):
        while True : 
            try:
                cmd_line = input(">>")
                args = cmd_line.split()
                if len(args) == 0 :
                    continue 
                cmd = args[0]
                if cmd == "help":
                    self._cmd_help()
                    continue
                if cmd == "exit":
                    exit()
                if cmd not in self.cmd_dict:
                    print("unknowen cmd : %s"%cmd)
                    continue 
                self.cmd_dict[cmd]["func"](arg_list = args[1:])

            except KeyboardInterrupt:
                exit()
           
            except Exception as e:
                print(e)
           
            

    #//cmd below 
    @ArgWrapper(cmd_show_argparser) 
    def _cmd_show(self, *, direction):
        if direction == "ingress":
            flows = self.ingress_flow_actions
        else:
            raise RuntimeError("unsupport show flow info with direction: %s"%direction)
        for id, flow in enumerate(flows): 
            print("%d : %s"%(id, flow.print_flow_info()))

    @ArgWrapper(cmd_create_argparser, use_res_args=True)
    def _cmd_create(self, *, direction, res_args):
        if direction == "ingress":
            self.ingress_flow_actions.append(FlowIngressAction(arg_list = res_args))
            print("%d: %s"%((len(self.ingress_flow_actions) - 1), self.ingress_flow_actions[-1].print_flow_info()))
        else:
            raise RuntimeError("unsupport show flow info with direction: %s"%direction)

    @ArgWrapper(cmd_add_argparser, use_res_args=True)
    def _cmd_add(self, *, direction, index, action_name, res_args):
        if direction == "ingress":
            if index >= len(self.ingress_flow_actions):
                raise RuntimeError("flow index %d out of bound"%index)
            self.ingress_flow_actions[index].add(action_name, res_args)
        else:
            raise RuntimeError("unsupport show flow info with direction: %s"%direction)

    @ArgWrapper(cmd_submit_argparser)
    def _cmd_submit(self, *, direction, index):
        if direction == "ingress":
            if index >= len(self.ingress_flow_actions):
                raise RuntimeError("flow index %d out of bound"%index)
            self.ingress_flow_actions[index].submit()
        else:
            raise RuntimeError("unsupport show flow info with direction: %s"%direction)

    def _cmd_help(self):
        for cmd , info in self.cmd_dict.items():
            print("%s : %s"%(cmd, info["desc"]))

if __name__ == '__main__':
    import sys
    ip = "127.0.0.1"
    t = Tool()
    t.run()
        