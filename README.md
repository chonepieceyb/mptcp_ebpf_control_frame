# README

eMPTCP is a framework that extends MPTCP developed based on eBPF.  eMPTCP has the following features: 

* **Modular and pluggable.**  Instead of using a monolithic programming model, eMPTCP allows a modular specification of policies as a software chain. Network operators can customize and dynamically plug their program into a chain (or part) of policies on MPTCP dynamically, without interrupting the running network services. These modules can be further shared and reused among multiple chains, thereby enhancing efficiency.
* **Adding new functionalities.** eMPTCP supports a wide range of MPTCP operations, including controllable path establishment, traffic scheduling, etc. By allowing inspection and manipulation of network packets, eMPTCP can utilize the views from different layers of network protocols, yielding unique insights and exerting control beyond the end hosts.
* **Higher pace of development.** With intent-based abstrac- tions and security-verified helper functions provided by eMPTCP, network operators can focus on the essential policy development without worrying about the details and security issues of the MPTCP kernel. 

![image-20220731104358638](/Users/ybchonepiece/Library/Application Support/typora-user-images/image-20220731104358638.png)

​																	    Fig.  Architecture of eMPTCP

fro more details, please read our paper.

## Install

**requirement** 

* clang 10.0.0
* llvm  10.0.0

* libbpf 0.7.0  https://github.com/libbpf/libbpf.git
* libxdp 1.3.0 https://github.com/xdp-project/xdp-tools.git
* bcc  https://github.com/iovisor/bcc.git
* cmake >= 3.16

**steps** 

1. we use cmake to compile the bpf-C and C++ code.  In the root dir of eMPTCP : 

```shell 
mkdir build 
cd build 
```

2. run cmake command to generate makefiles. Here you can use CMAKE_C_COMPILER option and CMAKE_CXX_COMPILER option to specify your C and C++ compiler.

```shell 
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ../
```

3. run make command:

```shell 
make -j 5  
make install 
```

**file organization** 

./src :  store all source files 

* ./src/bpf_kern: store all eBPF source files (actors and selectors)
* ./src/py: store all the python codes
* ./src/cc: store all the C++ codes

./bin : the binary file of emptcpd (daemon of eMPTCP project)

./install:  eBPF bytecode file compiled using llvm 

## Usage

eMPTCP is composed of normal program in user mode and eBPF program in kernel mode. In order to use eMPTCP,  you need to: 

1. load the compiled eBPF programs into the kernel.
2. use the user lib 
3. start emptcpd for specific actors/selectors

**loading eBPF programs** 

the script `./src/py/prog_loader.py`  is used to load eBPF bytecode in `./install` into the kernel  and attach them to the XDP and TC hook.

1. load and attach eBPF program into all network devices: 

```shell
sudo ./src/py/prog_loader.py -a --all
```

After loading, all BPF_MAP will be pinned to BPF VFS: `/sys/fs/bpf/emptcp`, and you can also use **bpftool** to check all the loaded maps and progs. 

2. detach 

```shell 
sudo ./src/py/prog_loader.py -d --all 
```

After detaching, all eBPF programs and pinned MAPs will be destroyed.

Please run `./src/py/prog_loader.py -h` for more details.

**using user lib** 

Our user space APIs is used to set eMPTCP policy chain easily. Please check API section for more details.

**emptcpd** 

emptcpd is used for packet injection.  If you use some specific actors, you need to start emptcpd: 

1. `recover_add_addr` , `rm_add_addr` actors is used to remove MP_ADD_ADDR option in the beginning of the MPTCP connection.  After removing MP_ADD_ADDR, you may need to recover the option, then you need to use `recover_add_addr` actor. 
2. `set_priority` , this actor is used to set the priority of the MPTCP subflow.  If you want to recover a subflow after setting backup, you need to use emptcpd

Please read `./docs/packet_injection.md` For the details of emptcpd and packet injection.

## API

**User Lib API** 

the core of development based on emptcp is policy chain,

to create a policy chain, you must:

1. create the structure selector chain (It should be noted that during running the structure of the selector chain should not be changed, meaning that the structure of the selector chain normally initialized as a global variable)
2. create an actor chain and add actors as you required. 
3. create policy chain based on actor chain and selector chain 
4. call the `set` method of PolicyChain to apply the policy chain to specific flows.

example: 

create a policy chain in Ingress path(XDP): 

```python 
from emptcp.PolicyChain import * 

#must be called before initialize PolicyChain, 
#the two method will check if the eBPF program have been loaded into kernel 
XDPSelectorChain.config()
XDPPolicyChain.config()

#create the structure of selector chain 
#assumed that the selector chain has tow selectors :
#1. ip_pair selector
#2. tcp_flow selecor 

sc = XDPSelectorChain()
sc.add("tcp2", selector_op_type_t.SELECTOR_OR)
sc.add("tcp4", selector_op_type_t.SELECTOR_AND)

#create action chian
#assumed that the actor chain has tow selectors: 
#1. set_recv_window
#2. rm_add_addr 

ac = XDPActionChain()
ac.add("set_recv_win", recv_win = 1600).add("rm_add_addr")
    
#create policy chain
pc = XDPPolicyChain(sc, ac)

#appliy the policy chain to flow with ip pair (172.16.12.128, 172.16.12.131) for example
# 0 means the index of the selector, as we defined before, index 0 represents ip_pair selector
pc.set(0, local_addr = "172.16.12.128", remote_addr = "172.16.12.131")
```

for egress path, use `TCSelectorChain TCActionChain TCPolicyChain` in the same way。

In the feature,  we will provide more detailed documents of all our selectors and actors. Currently please check `./src/py/emptcp/policy_actions.py` `./src/py/emptcp/policy_selectors.py`  for the details of selectors and actors.

**eBPF APIs** 

A lot of  useful eBPF APIs are provided for developing your own actors/selectors easily.  To create your own actors/selectors you need to include `./src/bpf_kern/common.h` and `./src/bpf_kern/utils.h`

We use XDP actor/selector as an example : 

```C
#code template for XDP selector 
#include "utils.h"
#include "common.h"
#include "errors.h"

#include "common.h"
#include "utils.h"
#include "error.h"

/*
*BPF_MAP definition for policy chain mechanism
*/

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_SELECTOR_NUM);
} xdp_selectors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_ACTION_NUM);
} xdp_actions SEC(".maps");

SEC("xdp")
int your_own_selector(struct xdp_md *ctx) 
{
/*Policy Chain SEC header begin*/
    int res;
    XDP_SELECTOR_PRE_SEC 
/*Policy Chain SEC header end*/

/*your own codes begin*/
        
#if the packet dismatch this selector 
CHECK_SELECTOR_NOMATCH(SELECTOR_OP);

#if the packet hit this selectr 
 CHECK_SELECTOR_MATCH(SELECTOR_OP);   
/*your own codes end*/

/*set the ACTION_CHAIN_ID according to the selector define */
    ACTION_CHAIN_ID = 0;
    
/*Policy Chain SEC footer begin*/
    XDP_SELECTOR_POST_SEC
/*Policy Chain SEC footer end*/
 
next_selector:                                  
   /*your own codes if go to next selector*/
    bpf_tail_call(ctx, &xdp_selectors, NEXT_IDX);
    res = -TAIL_CALL_FAIL;                     
    goto fail;                                 

action_entry:   
    /*your own codes if the packet hit the selector chain*/
    bpf_tail_call(ctx, &xdp_actions, XDP_ACTION_ENTRY);
    res = -TAIL_CALL_FAIL;                     
    goto fail;                                 

not_target:
     /*your own codes if the packet dismatch the selector chain\ */
    return XDP_PASS;

out_of_bound:
fail: 
    /*your own codes if any wrong with the selector chain\ */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```



```C
#code template of XDP actor 
#include "utils.h"
#include "common.h"
#include "errors.h"
/*
*BPF_MAP definition for policy chain mechanism
*/
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_ACTION_NUM);
} xdp_actions SEC(".maps");


SEC("xdp")
int your_own_actor(struct xdp_md *ctx) {
    
/*Policy Chain SEC header begin*/
    int res;
    XDP_POLICY_PRE_SEC
/*Policy Chain SEC header end*/
    
/*
* variable PARAM can be used to get your parameters
* asumed that the type of your parameter is __u16
*/
    xdp_action_t *a = (xdp_action_t *)(&POLICY);
	__u16 param = a->param.imme;
    
/*your own codes begin*/

/*your own codes end*/

/*Policy Chain SEC footer begin*/
    XDP_ACTION_POST_SEC
/*Policy Chain SEC footer end*/
        
next_action:                          
	/*your own codes if this actor finish*/
    
    bpf_tail_call(ctx, &xdp_actions, NEXT_IDX);
    res = -TAIL_CALL_FAIL;                      
    goto fail;

out_of_bound:
fail: 
    /*your own codes if this actor failed*/
    
    return XDP_PASS;

exit:
    /*your own codes if this actor chain finished*/
    return XDP_PASS;

}
char _license[] SEC("license") = "GPL";
```

for the selecor/actor for TC, APIs is just the same and you just need to slightly modified macro names.

Use `TC_POLICY_PRE_SEC  TC_ACTION_POST_SEC TC_SELECTOR_POST_SEC`