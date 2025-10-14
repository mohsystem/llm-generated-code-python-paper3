
import os
import threading
import hashlib
from pathlib import Path
from typing import Optional, Dict
from concurrent.futures import ThreadPoolExecutor, Future
import tempfile

class Task0:
    MAGIC = b"PROC"
    VERSION = 1
    MAX_PATH_LENGTH = 4096
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    
    def __init__(self, base_path: str):
        if not base_path or not base_path.strip():
            raise ValueError("Base path cannot be null or empty")
        
        self.base_directory = Path(base_path).resolve()
        
        if not self.base_directory.exists():
            raise ValueError("Base directory does not exist")
        
        if not self.base_directory.is_dir():
            raise ValueError("Base path is not a directory")
        
        self.file_locks: Dict[str, threading.Lock] = {}
        self.locks_lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    def _validate_and_resolve_path(self, filename: str) -> Path:
        if not filename or not filename.strip():
            raise ValueError("Filename cannot be null or empty")
        
        if len(filename) > self.MAX_PATH_LENGTH:
            raise ValueError("Filename exceeds maximum length")
        
        if ".." in filename or "~" in filename:
            raise SecurityError("Path traversal detected")
        
        resolved = (self.base_directory / filename).resolve()
        
        if not str(resolved).startswith(str(self.base_directory)):
            raise SecurityError("Resolved path outside base directory")
        
        if resolved.exists():
            if not resolved.is_file():
                raise ValueError("Path is not a regular file")
            if resolved.is_symlink():
                raise SecurityError("Symbolic links are not allowed")
        
        return resolved
    
    def _get_file_lock(self, canonical_key: str) -> threading.Lock:
        with self.locks_lock:
            if canonical_key not in self.file_locks:
                self.file_locks[canonical_key] = threading.Lock()
            return self.file_locks[canonical_key]
    
    def process_file(self, filename: str) -> Future:
        return self.executor.submit(self._process_file_internal, filename)
    
    def _process_file_internal(self, filename: str) -> str:
        try:
            file_path = self._validate_and_resolve_path(filename)
            canonical_key = str(file_path)
            
            lock = self._get_file_lock(canonical_key)
            
            with lock:
                if not file_path.exists():
                    return f"File not found: {filename}"
                
                file_size = file_path.stat().st_size
                if file_size > self.MAX_FILE_SIZE:
                    return f"File too large: {filename}"
                
                temp_fd, temp_path = tempfile.mkstemp(dir=self.base_directory, prefix=".proc_", suffix=".tmp")
                temp_path_obj = Path(temp_path)
                
                try:
                    os.close(temp_fd)
                    
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as reader:
                        content = self.MAGIC.decode('ascii') + str(self.VERSION) + "\\n"
                        
                        for line in reader:
                            if len(line) > 10000:
                                line = line[:10000]
                            content += line.upper()
                    
                    with open(temp_path_obj, 'w', encoding='utf-8') as writer:
                        writer.write(content)
                        writer.flush()
                        os.fsync(writer.fileno())
                    
                    output_path = self.base_directory / f"{filename}.processed"
                    temp_path_obj.replace(output_path)
                    
                    return f"Processed: {filename}"
                except Exception as e:
                    temp_path_obj.unlink(missing_ok=True)
                    raise
        except Exception as e:
            return f"Error processing {filename}: {str(e)}"
    
    def shutdown(self):
        self.executor.shutdown(wait=True)


def main():
    import shutil
    
    try:
        test_dir = Path(tempfile.mkdtemp(prefix="fileproc_test_"))
        
        (test_dir / "file1.txt").write_text("hello world", encoding='utf-8')
        (test_dir / "file2.txt").write_text("test data", encoding='utf-8')
        (test_dir / "file3.txt").write_text("sample content", encoding='utf-8')
        (test_dir / "file4.txt").write_text("another file", encoding='utf-8')
        (test_dir / "file5.txt").write_text("final test", encoding='utf-8')
        
        processor = Task0(str(test_dir))
        
        futures = [
            processor.process_file("file1.txt"),
            processor.process_file("file2.txt"),
            processor.process_file("file3.txt"),
            processor.process_file("file4.txt"),
            processor.process_file("file5.txt")
        ]
        
        for future in futures:
            print(future.result())
        
        processor.shutdown()
        
        shutil.rmtree(test_dir, ignore_errors=True)
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
