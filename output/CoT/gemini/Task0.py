import threading
import time
import queue

def file_processor(file_queue, thread_id):
    """Pulls filenames from a queue and processes them."""
    while not file_queue.empty():
        try:
            # Use non-blocking get to avoid waiting forever if queue becomes empty
            # between the while check and this call.
            file_name = file_queue.get_nowait()
        except queue.Empty:
            break

        print(f"Thread-{thread_id} started processing {file_name}")
        # Simulate file processing time
        time.sleep(1)
        print(f"Thread-{thread_id} finished processing {file_name}")
        file_queue.task_done()

def process_files(files, num_threads):
    """Sets up a queue and threads to process a list of files."""
    print("--- Python Concurrent File Processing ---")
    if not files:
        print("No files to process.")
        print("All files have been processed.\n")
        return

    file_queue = queue.Queue()
    for file_name in files:
        file_queue.put(file_name)

    threads = []
    for i in range(num_threads):
        # Create a thread and start it
        thread = threading.Thread(target=file_processor, args=(file_queue, i + 1))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    print("All files have been processed.\n")

if __name__ == "__main__":
    # Test Case 1
    process_files(["file1.log", "file2.data", "archive.zip", "image.jpg", "report.docx"], 3)
    
    # Test Case 2
    process_files(["document.pdf", "data.csv"], 2)
    
    # Test Case 3
    process_files(["single_file.txt"], 4)
    
    # Test Case 4
    process_files(["audio.mp3", "video.mp4", "backup.sql", "config.ini", "style.css", "script.js"], 4)
    
    # Test Case 5
    process_files([], 3) # No files