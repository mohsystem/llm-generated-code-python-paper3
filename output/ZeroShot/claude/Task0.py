
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Callable
import queue

class Task0:
    def __init__(self, directory_path: str, thread_pool_size: int):
        self.directory_path = directory_path
        self.file_locks = {}
        self.locks_lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=thread_pool_size)
        
    def _get_file_lock(self, file_name: str) -> threading.Lock:
        with self.locks_lock:
            if file_name not in self.file_locks:
                self.file_locks[file_name] = threading.Lock()
            return self.file_locks[file_name]
    
    def process_file(self, file_name: str, processor: Callable[[str], None]):
        def task():
            file_lock = self._get_file_lock(file_name)
            
            acquired = file_lock.acquire(timeout=5)
            if acquired:
                try:
                    file_path = os.path.join(self.directory_path, file_name)
                    
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        processor(file_path)
                        print(f"{threading.current_thread().name} processed: {file_name}")
                    else:
                        print(f"File not found: {file_name}")
                finally:
                    file_lock.release()
            else:
                print(f"{threading.current_thread().name} could not acquire lock for: {file_name}")
        
        self.executor.submit(task)
    
    def process_all_files(self, processor: Callable[[str], None]):
        if not os.path.exists(self.directory_path) or not os.path.isdir(self.directory_path):
            print(f"Invalid directory: {self.directory_path}")
            return
        
        files = [f for f in os.listdir(self.directory_path) if os.path.isfile(os.path.join(self.directory_path, f))]
        
        for file_name in files:
            self.process_file(file_name, processor)
    
    def shutdown(self):
        self.executor.shutdown(wait=True)


if __name__ == "__main__":
    test_dir = "test_files_py"
    
    if not os.path.exists(test_dir):
        os.mkdir(test_dir)
    
    for i in range(1, 6):
        with open(os.path.join(test_dir, f"file{i}.txt"), 'w') as f:
            f.write(f"Test content for file {i}\\n")
    
    print("Test Case 1: Process multiple files concurrently")
    system1 = Task0(test_dir, 3)
    def processor1(file_path):
        time.sleep(0.1)
        with open(file_path, 'r') as f:
            content = f.read()
    
    system1.process_all_files(processor1)
    system1.shutdown()
    time.sleep(1)
    
    print("\\nTest Case 2: Multiple threads accessing same file")
    system2 = Task0(test_dir, 5)
    for i in range(3):
        system2.process_file("file1.txt", lambda fp: time.sleep(0.2))
    system2.shutdown()
    time.sleep(1)
    
    print("\\nTest Case 3: Process with single thread pool")
    system3 = Task0(test_dir, 1)
    system3.process_all_files(lambda fp: time.sleep(0.05))
    system3.shutdown()
    time.sleep(1)
    
    print("\\nTest Case 4: Process non-existent file")
    system4 = Task0(test_dir, 2)
    system4.process_file("nonexistent.txt", lambda fp: print("Should not reach here"))
    system4.shutdown()
    time.sleep(0.5)
    
    print("\\nTest Case 5: Process with large thread pool")
    system5 = Task0(test_dir, 10)
    system5.process_all_files(lambda fp: time.sleep(0.1))
    system5.shutdown()
    
    for file in os.listdir(test_dir):
        os.remove(os.path.join(test_dir, file))
    os.rmdir(test_dir)
