import threading
import os
import time
import queue
import shutil

DIR_PATH = "python_test_files"
NUM_FILES = 5  # Test case: 5 files
NUM_THREADS = 3

def file_processor(file_queue, thread_id):
    """Worker function to process files from a queue."""
    while not file_queue.empty():
        try:
            # Get a file path from the queue without blocking
            file_path = file_queue.get_nowait()
        except queue.Empty:
            # This can happen in a race condition, just exit the loop
            break

        print(f"Thread {thread_id} is processing file: {os.path.basename(file_path)}")
        try:
            # Simulate processing time
            time.sleep(0.1)
            
            # Append a message to the file
            with open(file_path, 'a') as f:
                f.write(f"\nProcessed by Thread {thread_id}")
            
            print(f"Thread {thread_id} finished processing file: {os.path.basename(file_path)}")
        except Exception as e:
            print(f"Thread {thread_id} encountered an error processing {os.path.basename(file_path)}: {e}")
        finally:
            # Signal that the task is done
            file_queue.task_done()

def setup_test_environment():
    """Creates a directory and test files."""
    print("Setting up test environment...")
    if os.path.exists(DIR_PATH):
        shutil.rmtree(DIR_PATH)
    os.makedirs(DIR_PATH)
    
    for i in range(1, NUM_FILES + 1):
        file_path = os.path.join(DIR_PATH, f"test_file_{i}.txt")
        with open(file_path, 'w') as f:
            f.write(f"This is test file {i}.")
    print(f"{NUM_FILES} test files created in {DIR_PATH}")

def cleanup_test_environment():
    """Removes the directory and its contents."""
    print("\nCleaning up test environment...")
    if os.path.exists(DIR_PATH):
        shutil.rmtree(DIR_PATH)
        print("Test directory and files deleted.")

def main():
    """Main function to run the concurrent file processing."""
    # 1. Setup: Create directory and 5 test files
    setup_test_environment()

    # 2. Create a thread-safe queue and populate it
    file_queue = queue.Queue()
    for filename in os.listdir(DIR_PATH):
        file_path = os.path.join(DIR_PATH, filename)
        file_queue.put(file_path)

    print(f"\nStarting {NUM_THREADS} threads to process {file_queue.qsize()} files.")
    
    # 3. Create and start worker threads
    threads = []
    for i in range(1, NUM_THREADS + 1):
        thread = threading.Thread(target=file_processor, args=(file_queue, i))
        threads.append(thread)
        thread.start()

    # 4. Wait for all threads to complete their work
    for thread in threads:
        thread.join()

    print("\nAll processing tasks are complete.")
    
    # 5. Cleanup: Remove the directory and its contents
    cleanup_test_environment()

if __name__ == "__main__":
    main()