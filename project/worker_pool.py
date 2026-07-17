import queue
import traceback
import threading

class WorkerPool:
    def __init__(self, target, min_workers= 2, max_workers= 100, idle_time= 30):
        self.queue= queue.Queue()
        self.target= target
        self.min_workers= min_workers
        self.max_workers= max_workers
        self.idle_time= idle_time
        self.active_workers= 0
        self.lock= threading.Lock()

        for _ in range(self.min_workers):
            self.add_worker()

    # Create more Workers
    def add_worker(self):
        with self.lock:
            if self.active_workers< self.max_workers:
                t= threading.Thread(target= self.worker_loop, daemon= True)
                t.start()
                self.active_workers+= 1
                print(f"+ Scaled Up to {self.active_workers} workers automatically!")

    # As long as the thread is not told to shut down, it will run
    def worker_loop(self):
        while True:
            try:
                data, addr= self.queue.get(timeout= self.idle_time)
                if data is None:
                    print("- Worker thread safely shut down.")
                    self.queue.task_done() 
                    break
                try:
                    self.target(data, addr)
                except Exception as e:
                    traceback.print_exc()
                finally:
                    self.queue.task_done()

            except queue.Empty:
                with self.lock:
                    if self.active_workers> self.min_workers:
                        self.active_workers-= 1
                        print(f"Scaled Down to {self.active_workers} workers automatically!")
                        return

    # Each request is added to the queue. If the queue overflows, new workers are added
    def submit(self, data, addr):
        self.queue.put((data, addr))
        if self.queue.qsize()> self.active_workers and self.active_workers< self.max_workers:
            self.add_worker()

    # Method that tears down all threads
    def shutdown(self):
        for _ in range(self.active_workers):
            self.queue.put((None, None))

        self.queue.join()
