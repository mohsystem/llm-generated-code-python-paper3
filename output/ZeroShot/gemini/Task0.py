import os
import threading
import queue
import time
import random
import shutil

# Lock for ensuring print statements are not garbled
print_lock = threading.Lock()

def process_file(file_path):
    """
    Simulates processing a single file.
    This function is guaranteed to be called by only one thread for any given file
    because the file paths are distributed via a thread-safe queue.
    """
    thread_name = threading.current_thread().name
    with print_lock:
        print(f"{thread_name} started processing: {os.path.basename(file_path)}")
    
    # Simulate work
    time.sleep(random.uniform(0.05, 0.1))

    with print_lock:
        print(f"{thread_name} finished processing: {os.path.basename(file_path)}")

def worker(file_queue):
    """
    Worker thread function that continuously fetches a file from the queue and processes it.
    """
    while True:
        try:
            # Get a file path from the queue. block=False raises Empty exception immediately.
            file_path = file_queue.get_nowait()
        except queue.Empty:
            # No more work to be done
            break
        else:
            process_file(file_path)
            file_queue.task_done()

def run_test(directory_path, num_files, num_threads):
    """
    Sets up the environment, runs the simulation, and cleans up.
    """
    print("\n--- Running Test ---")
    print(f"Directory: {directory_path}, Files: {num_files}, Threads: {num_threads}")
    
    try:
        # 1. Setup: Create directory and dummy files
        if not os.path.exists(directory_path):
            os.makedirs(directory_path)
        for i in range(1, num_files + 1):
            with open(os.path.join(directory_path, f"file_{i}.txt"), "w") as f:
                f.write("dummy content")

        # 2. Create a thread-safe queue and populate it with files
        file_queue = queue.Queue()
        file_list = [os.path.join(directory_path, f) for f in os.listdir(directory_path)]
        for file_path in file_list:
            file_queue.put(file_path)

        # 3. Create and start worker threads
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=worker, args=(file_queue,), name=f"Worker-{i+1}")
            threads.append(thread)
            thread.start()

        # 4. Wait for all threads to complete
        for thread in threads:
            thread.join()

    finally:
        # 5. Cleanup: Delete the directory and its contents
        if os.path.exists(directory_path):
            shutil.rmtree(directory_path)
            print(f"Cleaned up directory: {directory_path}")
    print("--- Test Finished ---")

# Main execution block with 5 test cases
if __name__ == "__main__":
    try:
        # Test Case 1: More files than threads
        run_test("python_test_dir_1", 5, 2)
        # Test Case 2: Equal files and threads
        run_test("python_test_dir_2", 4, 4)
        # Test Case 3: More threads than files
        run_test("python_test_dir_3", 3, 5)
        # Test Case 4: Single thread
        run_test("python_test_dir_4", 5, 1)
        # Test Case 5: Large number of files
        run_test("python_test_dir_5", 20, 4)
    except Exception as e:
        print(f"An error occurred: {e}")