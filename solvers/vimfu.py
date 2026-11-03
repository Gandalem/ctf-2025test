"""Execute the CTF's supplied Vim macro on the supplied lock file.

The actual result is read from Vim register z, as specified by this challenge.
Never use this runner with untrusted macro files: Vim macros can invoke shell
commands. Only execute the bundled public CTF fixture or files you trust.
"""
import argparse
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

def solve(key_path: Path, lock_path: Path, executable: str = "vim") -> str:
    vim = shutil.which(executable)
    if vim is None:
        raise RuntimeError(f"Vim executable not found: {executable}")
    if not key_path.is_file() or not lock_path.is_file():
        raise ValueError("Missing original Vim macro key or text lock fixture")
    # The challenge handout uses <CR>, <ESC> and <BS> notation; translate them
    # into raw character sequences before loading the macro register.
    macro = key_path.read_bytes().replace(b"<CR>", b"\r")
    macro = macro.replace(b"<ESC>", b"\x1b").replace(b"<BS>", b"\x08")
    # Use a temporary macro file and Vimscript readfile, not interpolated code.
    # readfile(..., 'b') maps embedded NUL to newline, but macro has no NULs.
    with tempfile.TemporaryDirectory(prefix="ctf-vimfu-") as work:
        tmp = Path(work)
        (tmp / "macro").write_bytes(macro)
        script = tmp / "run.vim"
        output = tmp / "result.txt"
        quote = lambda p: str(p).replace("'", "''")
        script.write_text(
            "set nocompatible\n"
            "set nomore\n"
            "set noswapfile\n"
            f"execute 'edit ' . fnameescape('{quote(lock_path.resolve())}')\n"
            f"let @q = readfile('{quote(tmp / 'macro')}', 'b')[0]\n"
            "normal gg0\n"
            "normal @q\n"
            f"call writefile([getreg('z')], '{quote(output)}')\n"
            "qa!\n", encoding="utf-8"
        )
        result = subprocess.run(
            [vim, "-Nu", "NONE", "-N", "-n", "-es", "-S", str(script)],
            capture_output=True, timeout=15, cwd=work, check=False,
            env={**os.environ, "HOME": str(tmp)},
        )
        if not output.exists():
            raise RuntimeError(
                "Macro did not write Vim register z: " +
                result.stderr.decode(errors="replace")[-1000:]
            )
        value = output.read_text(encoding="utf-8").strip()
        # The Vim macro can yank a larger paragraph around the embedded flag;
        # inspect the genuine register contents rather than assume it is only
        # a flag string. Do not insert any expected answer into solver logic.
        matches = re.findall(r"DUCTF\{[^{}\r\n]{1,200}\}", value)
        if not matches:
            raise ValueError(f"No DUCTF flag found in register z: {value!r}; "
                             f"vim exited with {result.returncode}")
        if len(set(matches)) != 1:
            raise ValueError(f"Multiple distinct candidate flags: {matches!r}")
        if result.returncode:
            raise RuntimeError(f"Vim macro exited with status {result.returncode}")
        return matches[0]

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("key", type=Path)
    parser.add_argument("lock", type=Path)
    args = parser.parse_args()
    print(solve(args.key, args.lock))

if __name__ == "__main__":
    main()
