#ifndef MPTCP_EBPF_CONTROL_FRAME_ERROR_H
#define MPTCP_EBPF_CONTROL_FRAME_ERROR_H

#define FAILED_ADJUST_XDP_META          1001
#define FAILED_GET_XDP_ACTION           1002
#define INTERNAL_IMPOSSIBLE             1003
#define INVALID_ACTION_ARGUMENT         1004
#define POP_XDP_ACTION_FAILED           1005
#define XDP_GROW_TCP_HEADER_FAIL        1006
#define XDP_ADD_TCP_OPT_FAIL            1007
#define XDP_TAIL_CALL_FAIL              1008
#define NOT_TARGET                      1

#endif
