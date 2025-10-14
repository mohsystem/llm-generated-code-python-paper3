import os
import stat

def create_executable_script(directory: str, content: str) -> bool:
    try:
        if not content:
            content = "#!/bin/bash\necho \"Hello from script.sh\"\n"
        dir_path = "." if directory is None or directory == "" or directory == "." else directory
        script_path = os.path.join(dir_path, "script.sh")

        parent = os.path.dirname(script_path)
        if parent and parent != "":
            os.makedirs(parent, exist_ok=True)

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(content)

        mode = os.stat(script_path).st_mode
        os.chmod(script_path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH | stat.S_IRGRP | stat.S_IROTH)
        return True
    except Exception:
        return False

if __name__ == "__main__":
    tests = [
        (".", "#!/bin/bash\necho \"Python test 1\""),
        ("py_out1", "#!/bin/bash\necho \"Python test 2\""),
        ("py_out2/nested", "#!/bin/bash\necho \"Python test 3\""),
        ("py out3/spaced", "#!/bin/bash\necho \"Python test 4\""),
        ("py_out4/a/b", "#!/bin/bash\necho \"Python test 5\""),
    ]
    for i, (d, c) in enumerate(tests, 1):
        res = create_executable_script(d, c)
        print(f"Test {i} ({d}): {'success' if res else 'failed'}")