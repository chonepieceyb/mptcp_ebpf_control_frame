import heapq
from multiprocessing import  Process, Queue, Value
import multiprocessing
import queue 

running = True 
q = Queue()

def consume(q, running):
    while running.value or not q.empty():
        try:
            item = q.get(False, timeout = 0.01)
            print("consume: %d"%item)
        except queue.Empty:
            continue 
        except KeyboardInterrupt:
            continue 

def produce(q, running):
    count = 0
    while(running.value):
        try:
            q.put(count)
            print("produce: %d"%count)
            count+=1
        except KeyboardInterrupt:
            continue 
    
'''
python consumer-producer example

running = True 
q = queue.Queue()
def consume(q):
    while running or not q.empty():
        try:
            item = q.get(False, timeout = 0.01)
            print("consume: %d"%item)
            q.task_done()
        except queue.Empty :
            continue 

def produce(q):
    count = 0
    while(running):
        q.put(count)
        print("produce: %d"%count)
        count+=1
    q.join()

if __name__ == '__main__':
    running = True 
    p = threading.Thread(target = produce, args=[q])
    c = threading.Thread(target = consume, args=[q])
    p.start()
    c.start()
    while True:
        try:
            pass
        except KeyboardInterrupt:
            running = False
            p.join()
            c.join()
            exit()
'''
if __name__ == '__main__':
    '''
        running = Value("b", True)
        q = Queue()
        p = Process(target = produce, args=[q, running])
        c = Process(target = consume, args=[q, running])
        p.start()
        c.start()
        pq = queue.PriorityQueue()
        pq.put()
        while True:
            try:
                continue
            except KeyboardInterrupt:
                running.value = False
                print("p join")
                p.join()
                print("c join")
                c.join()
                exit()
    '''
    import heapq
    q = [] 
    heapq.heappush(q)
