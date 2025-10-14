import os
import threading
import time
import queue
import shutil
from pathlib import Path
from typing import List

# Thread-safe queue to hold file paths
file_queue = queue.Queue()

class FileProcessor(threading.Thread):
    def __init__(self, thread_id: int):
        super().__init__()
        self.thread_id = thread_id

    def run(self):
        """Processes files from the global queue until it's empty."""
        while not file_queue.empty():
            try:
                file_path = file_queue.get_nowait()
                self.process_file(file_path)
                file_queue.task_done()
            except queue.Empty:
                break # Queue is empty

    def process_file(self, file_path: Path):
        """Simulates file processing."""
        print(f"Thread {self.thread_id}: Starting processing of {file_path.name}")
        try:
            # Simulate work by reading the file and sleeping
            with file_path.open('r', encoding='utf-8') as f:
                f.read()
            time.sleep(0.1)
            print(f"Thread {self.thread_id}: Finished processing of {file_path.name}")
        except IOError as e:
            print(f"Thread {self.thread_id}: Error processing file {file_path.name}: {e}")
        except Exception as e:
            print(f"Thread {self.thread_id}: An unexpected error occurred with {file_path.name}: {e}")

def process_files_concurrently(directory_path_str: str, num_threads: int):
    """
    Lists files in a directory and processes them concurrently using a thread pool.
    """
    base_dir = Path(directory_path_str).resolve()
    
    # Security: Validate the directory exists and is a directory
    if not base_dir.is_dir():
        print(f"Error: Directory not found or is not a directory: {directory_path_str}")
        return

    # Clear queue for subsequent runs in the same process
    while not file_queue.empty():
        try:
            file_queue.get_nowait()
        except queue.Empty:
            break

    # Security: List only regular files and ensure they are within the base directory.
    # The check base_dir in p.parents is a simple way to prevent traversal,
    # but resolve() already helps significantly.
    try:
        files_to_process = [p for p in base_dir.iterdir() if p.is_file() and base_dir in p.resolve().parents]
    except OSError as e:
        print(f"Error listing files in directory {base_dir}: {e}")
        return

    if not files_to_process:
        print("No files to process in the directory.")
        return

    for f in files_to_process:
        file_queue.put(f)

    threads: List[FileProcessor] = []
    for i in range(num_threads):
        thread = FileProcessor(thread_id=i + 1)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
        
    # Wait for all tasks in the queue to be processed.
    file_queue.join()

def main():
    """Main function with test cases."""
    # Create a temporary directory and files for testing
    temp_dir = Path("./temp_test_dir_python")
    try:
        # Setup
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        temp_dir.mkdir(parents=True, exist_ok=True)
        print(f"Created temporary directory: {temp_dir.resolve()}")

        for i in range(1, 11):
            with open(temp_dir / f"test_file_{i}.txt", "w", encoding="utf-8") as f:
                f.write(f"This is test file {i}")

        # --- Test Cases ---
        print("\n--- Test Case 1: Processing 10 files with 4 threads ---")
        process_files_concurrently(str(temp_dir), 4)

        print("\n--- Test Case 2: Processing with 1 thread ---")
        process_files_concurrently(str(temp_dir), 1)

        print("\n--- Test Case 3: Processing with 8 threads ---")
        process_files_concurrently(str(temp_dir), 8)

        print("\n--- Test Case 4: Non-existent directory ---")
        process_files_concurrently("./non_existent_dir", 4)
        
        print("\n--- Test Case 5: Empty directory ---")
        empty_dir = Path("./empty_test_dir_python")
        empty_dir.mkdir(exist_ok=True)
        process_files_concurrently(str(empty_dir), 4)
        empty_dir.rmdir()

    except Exception as e:
        print(f"An error occurred in main: {e}")
    finally:
        # Cleanup
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
            print("Cleaned up temporary directory.")

if __name__ == "__main__":
    main()