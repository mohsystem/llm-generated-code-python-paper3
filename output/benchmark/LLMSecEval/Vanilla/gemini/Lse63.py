import os

class Lse63:
    """
    A container class to satisfy the naming requirement. Python is not
    strictly class-based for scripts, so this is for convention.
    """
    @staticmethod
    def process_file(input_file_path, output_file_path):
        """
        Reads the contents of a file into a buffer, calculates a simple checksum,
        and saves the number of bytes read and the checksum to another file.
        """
        try:
            with open(input_file_path, 'rb') as f_in:
                buffer = f_in.read()

            bytes_read = len(buffer)
            checksum = 0
            
            # If the buffer is empty, bytes_read is 0, and the checksum remains 0.
            if bytes_read > 0:
                checksum = sum(buffer) % 256

            result = f"Bytes read: {bytes_read}\nChecksum: {checksum}"

            with open(output_file_path, 'w') as f_out:
                f_out.write(result)
                
        except IOError as e:
            print(f"An I/O error occurred: {e}")

    @staticmethod
    def main():
        """Main execution block with 5 test cases."""
        test_cases = {
            "test1_in.txt": b"",            # Empty file
            "test2_in.txt": b"A",            # Single character (ASCII 65)
            "test3_in.txt": b"Hello",        # Simple string
            "test4_in.txt": b"\x80\x80",    # Non-empty, checksum 0 (128+128=256)
            "test5_in.txt": b"\x00"          # Null byte
        }

        test_num = 1
        for input_filename, content in test_cases.items():
            output_filename = f"test{test_num}_out.txt"
            
            print(f"--- Test Case {test_num} ---")
            print(f"Input File: {input_filename}")
            
            try:
                # 1. Create input file with specified content
                with open(input_filename, 'wb') as f:
                    f.write(content)

                # 2. Process the file
                Lse63.process_file(input_filename, output_filename)
                
                # 3. Read and display the output file content for verification
                if os.path.exists(output_filename):
                    with open(output_filename, 'r') as f:
                        output_content = f.read()
                        print(f"Output from {output_filename}:")
                        print(output_content, end='')
                else:
                    print(f"Output file {output_filename} was not created.")

            except Exception as e:
                print(f"Error during test case {test_num}: {e}")
            finally:
                # 4. Clean up created files
                if os.path.exists(input_filename):
                    os.remove(input_filename)
                if os.path.exists(output_filename):
                    os.remove(output_filename)
                print(f"\n---------------------\n")
                test_num += 1

if __name__ == "__main__":
    Lse63.main()