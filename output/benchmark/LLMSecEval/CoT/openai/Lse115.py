import subprocess

class Lse115:
    @staticmethod
    def print_fmt(fmt: str, *args) -> str:
        return (fmt % args) if args else fmt

    @staticmethod
    def exec_command(cmd: str) -> str:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return (res.stdout or "") + (res.stderr or "")

if __name__ == "__main__":
    cmds = [
        Lse115.print_fmt("ls"),
        Lse115.print_fmt("ls %s", "-l"),
        Lse115.print_fmt("ls %s %s", "-a", "."),
        Lse115.print_fmt("ls %s %s", "-1", ".."),
        Lse115.print_fmt("ls %s %s %s", "-l", "-a", "."),
    ]
    for i, c in enumerate(cmds, 1):
        print(f"Command #{i}: {c}")
        print("Output:")
        print(Lse115.exec_command(c))