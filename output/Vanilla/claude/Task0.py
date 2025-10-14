
import os
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Callable
import shutil

class Task0:
    def __init__(self, thread_pool_size):
        self.file_locks = {}
        self.locks_lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=thread_pool_size)
    
    def _get_lock(self, file_path):
        with self.locks_lock:
            if file_path not in self.file_locks:
                self.file_locks[file_path] = threading.Lock()
            return self.file_locks[file_path]
    
    def process_file(self, file_path, processor):
        def task():
            lock = self._get_lock(file_path)
            try:
                lock.acquire()
                print(f"{threading.current_thread().name} acquired lock for: {file_path}")
                processor(file_path)
                print(f"{threading.current_thread().name} finished processing: {file_path}")
            except Exception as e:
                print(f"Error processing file {file_path}: {str(e)}")
            finally:
                lock.release()
                print(f"{threading.current_thread().name} released lock for: {file_path}")
        
        self.executor.submit(task)
    
    def process_directory(self, directory_path, processor):
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.process_file(file_path, processor)
        except Exception as e:
            print(f"Error reading directory: {str(e)}")
    
    def shutdown(self):
        self.executor.shutdown(wait=True)
    
    def is_file_being_processed(self, file_path):
        with self.locks_lock:
            if file_path in self.file_locks:
                return self.file_locks[file_path].locked()
        return False


def create_test_directory(dir_name, num_files):
    Path(dir_name).mkdir(parents=True, exist_ok=True)
    for i in range(num_files):
        file_path = os.path.join(dir_name, f"file{i}.txt")
        with open(file_path, 'w') as f:
            f.write(f"Test content for file {i}")


def cleanup_test_directories():
    for i in range(1, 6):
        dir_name = f"test_dir{i}"
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)


if __name__ == "__main__":
    # Test case 1: Process multiple files concurrently
    print("=== Test Case 1: Multiple Files Processing ===")
    system1 = Task0(3)
    test_dir1 = "test_dir1"
    create_test_directory(test_dir1, 3)
    
    def processor1(file_path):
        time.sleep(1)
        print(f"Processed: {file_path}")
    
    system1.process_directory(test_dir1, processor1)
    system1.shutdown()
    time.sleep(1)
    
    # Test case 2: Same file accessed by multiple threads
    print("\\n=== Test Case 2: Same File Multiple Threads ===")
    system2 = Task0(3)
    test_dir2 = "test_dir2"
    create_test_directory(test_dir2, 1)
    test_file = os.path.join(test_dir2, "file0.txt")
    
    for i in range(3):
        system2.process_file(test_file, processor1)
    system2.shutdown()
    time.sleep(1)
    
    # Test case 3: Large number of files
    print("\\n=== Test Case 3: Large Number of Files ===")
    system3 = Task0(5)
    test_dir3 = "test_dir3"
    create_test_directory(test_dir3, 10)
    
    def processor3(file_path):
        time.sleep(0.5)
        print(f"Quick process: {file_path}")
    
    system3.process_directory(test_dir3, processor3)
    system3.shutdown()
    time.sleep(1)
    
    # Test case 4: File content modification
    print("\\n=== Test Case 4: File Content Modification ===")
    system4 = Task0(2)
    test_dir4 = "test_dir4"
    create_test_directory(test_dir4, 2)
    
    def processor4(file_path):
        with open(file_path, 'a') as f:
            f.write(f"\\nProcessed by {threading.current_thread().name}")
        time.sleep(0.8)
    
    system4.process_directory(test_dir4, processor4)
    system4.shutdown()
    time.sleep(1)
    
    # Test case 5: Error handling
    print("\\n=== Test Case 5: Error Handling ===")
    system5 = Task0(2)
    
    def processor5(file_path):
        if "error" in file_path:
            raise RuntimeError("Simulated error")
        time.sleep(0.5)
        print(f"Successfully processed: {file_path}")
    
    system5.process_file("test_dir5/error_file.txt", processor5)
    system5.process_file("test_dir5/good_file.txt", processor5)
    system5.shutdown()
    time.sleep(1)
    
    cleanup_test_directories()
