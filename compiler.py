import os
import py_compile

def check_syntax(source_dir, logfile):
    # Ensure the output directory exists
    # os.makedirs(output_dir, exist_ok=True)

    # Walk through the source directory to find Python files
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            if file.endswith('.py'):
                source_file = os.path.join(root, file)
                relative_path = os.path.relpath(root, source_dir)
                # output_path = os.path.join(output_dir, relative_path)
                # os.makedirs(output_path, exist_ok=True)

                # log_file = os.path.join(output_path, os.path.splitext(file)[0] + '.log')

                try:
                    print(f"Checking syntax for {source_file}")
                    py_compile.compile(source_file, doraise=True)
                    log_message = f"Syntax check successful: {source_file}\n"
                except py_compile.PyCompileError as e:
                    log_message = f"Syntax check failed for {source_file}:\n{e}\n"

                with open(logfile, 'a') as log:
                    log.write(log_message)

                print(log_message)

if __name__ == "__main__":
    source_directory = "./output/gtp4o"  # Replace with the path to your source directory
    logfile = "gtp4o_syntax_log.log"
    check_syntax(source_directory, logfile)
