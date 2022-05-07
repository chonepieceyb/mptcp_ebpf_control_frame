#-*- coding:utf-8 -*-

'''

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
'''
