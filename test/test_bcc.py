from bcc import BPF 

prog = """
struct test_perf_table_t { 
  int key; 
  u32 leaf; 
  /* map.perf_submit(ctx, data, data_size) */ 
  int (*perf_submit) (void *, void *, u32); 
  int (*perf_submit_skb) (void *, u32, void *, u32); 
  u32 max_entries; 
}; 
__attribute__((section("maps/perf_output:/sys/fs/bpf/test_perf"))) 
struct test_perf_table_t test_perf = { .max_entries = 0 };
"""

if __name__ == '__main__':
    bpf = BPF(text = prog)