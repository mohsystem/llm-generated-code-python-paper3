
import os
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Dict

class Task0:
    def __init__(self, base_directory: str, thread_pool_size: int):
        self.file_locks: Dict[str, threading.Lock] = {}
        self.locks_dict_lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=thread_pool_size)
        self.base_directory = self._validate_and_normalize_path(base_directory)
    
    def _validate_and_normalize_path(self, path: str) -> str:
        try:
            normalized_path = Path(path).resolve()
            if not normalized_path.exists():
                normalized_path.mkdir(parents=True, exist_ok=True)
            return str(normalized_path)
        except Exception as e:
            raise ValueError(f"Invalid directory path: {path}")
    
    def _is_path_safe(self, file_path: str) -> bool:
        try:
            requested_path = Path(file_path).resolve()
            base_path = Path(self.base_directory).resolve()
            return str(requested_path).startswith(str(base_path))
        except Exception:
            return False
    
    def _get_file_lock(self, full_path: str) -> threading.Lock:
        with self.locks_dict_lock:
            if full_path not in self.file_locks:
                self.file_locks[full_path] = threading.Lock()
            return self.file_locks[full_path]
    
    def process_file(self, file_name: str):
        self.executor.submit(self._process_file_task, file_name)
    
    def _process_file_task(self, file_name: str):
        full_path = os.path.join(self.base_directory, file_name)
        
        if not self._is_path_safe(full_path):
            print(f"Security violation: Path traversal attempt detected for {file_name}", flush=True)
            return
        
        lock = self._get_file_lock(full_path)
        
        acquired = lock.acquire(timeout=5)
        if acquired:
            try:
                self._process_file_content(full_path)
            finally:
                lock.release()
        else:
            print(f"Timeout: Could not acquire lock for {file_name}", flush=True)
    
    def _process_file_content(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                print(f"Thread {threading.current_thread().ident} processing: {file_path}", flush=True)
                line_count = sum(1 for _ in file)
                print(f"Thread {threading.current_thread().ident} completed: {file_path} ({line_count} lines)", flush=True)
        except FileNotFoundError:
            print(f"Error: File not found {file_path}", flush=True)
        except Exception as e:
            print(f"Error processing file {file_path}: {str(e)}", flush=True)
    
    def shutdown(self):
        self.executor.shutdown(wait=True, timeout=60)

if __name__ == "__main__":
    import tempfile
    
    test_dir = os.path.join(tempfile.gettempdir(), "test_concurrent_files")
    os.makedirs(test_dir, exist_ok=True)
    
    for i in range(1, 6):
        test_file = os.path.join(test_dir, f"test_file_{i}.txt")
        with open(test_file, 'w') as f:
            for j in range(100):
                f.write(f"Test data line {j} in file {i}\\n")
    
    processor = Task0(test_dir, 3)
    
    print("Test Case 1: Processing multiple files concurrently")
    processor.process_file("test_file_1.txt")
    processor.process_file("test_file_2.txt")
    processor.process_file("test_file_3.txt")
    
    print("\\nTest Case 2: Multiple threads attempting same file")
    processor.process_file("test_file_1.txt")
    processor.process_file("test_file_1.txt")
    
    print("\\nTest Case 3: Processing remaining files")
    processor.process_file("test_file_4.txt")
    processor.process_file("test_file_5.txt")
    
    print("\\nTest Case 4: Path traversal attack attempt")
    processor.process_file("../../../etc/passwd")
    
    print("\\nTest Case 5: Non-existent file")
    processor.process_file("non_existent_file.txt")
    
    processor.shutdown()
