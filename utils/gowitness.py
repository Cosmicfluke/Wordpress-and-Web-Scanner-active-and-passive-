# Optional screenshot helper wrapping the gowitness binary.
# No-ops silently if gowitness isn't on PATH.

import shutil
import subprocess
from colorama import Fore, Style

_warned = False


def available():
    return shutil.which("gowitness") is not None


def screenshot(url, output_dir="screenshots"):
    global _warned
    if not available():
        if not _warned:
            print(f"{Fore.YELLOW}[!] gowitness not found — skipping screenshots{Style.RESET_ALL}")
            _warned = True
        return None
    try:
        subprocess.run(
            ["gowitness", "single", url, "--destination", output_dir],
            capture_output=True, timeout=20, check=False,
        )
        return output_dir
    except Exception as e:
        print(f"{Fore.RED}[ERROR] gowitness: {e}{Style.RESET_ALL}")
        return None
