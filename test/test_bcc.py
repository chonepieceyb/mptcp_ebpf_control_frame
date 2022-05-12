from bcc import BPF 
from pexecute.process import ProcessLoom
from math import sqrt
import time 

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
def func(batch_size):
  for i in range(batch, batch_size):
      sqrt(i**2)

if __name__ == '__main__':
  '''
    batch= 1
    loom = ProcessLoom(max_runner_cap=batch)
    num = 10000000
    batch_size = num //batch
    print(batch)
    print(batch_size)
    b = round(time.time()*1000)
    for i in range(batch):
        loom.add_function(func, [batch_size])
    output = loom.execute()
    e = round(time.time()*1000)
    print(e-b)
    
    b = round(time.time()*1000)
    for i in range(num):
      sqrt(i**2)
    e = round(time.time()*1000)
    print(e-b)
  '''
  class B:
    def __init__(self):
      self.b = 1

  class A:
    def __init__(self):
      self.b = B()

  def func(a):
    a.b.b  = 2
    return a.b
  a = A()
  batch= 1
  loom = ProcessLoom(max_runner_cap=batch)

  loom.add_function(func, [a])
  #func(a)
  o = loom.execute()
  print(a.b.b)

  b2 = o[0]["output"]
  b2.b = 3
  print(a.b.b)
