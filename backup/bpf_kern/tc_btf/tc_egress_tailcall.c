#include "common.h"


struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 4);
} tc_egress_tailcall SEC(".maps");
