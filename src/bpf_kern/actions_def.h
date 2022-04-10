#ifndef MPTCP_EBPF_CONTROL_FRAME_ACTIONS_DEF_H
#define MPTCP_EBPF_CONTROL_FRAME_ACTIONS_DEF_H

//define tail call index here 

#define DEFAULT_ACTION 0
#define SET_RECV_WIN_IN_AID  1
#define SET_FLOW_PRIO_IN_AID 2

#define XDP_ACTION_META_BITMAP (0 |             \
        (0 << (SET_RECV_WIN_IN_AID)) |          \
        (0 << (SET_FLOW_PRIO_IN_AID)))

#endif 
