# Shared path validation for any file path that originates from a CLI
# argument (--json, --markdown, --plugin-wordlist). Doesn't block
# legitimate use, just rejects the classic path-traversal red flags
# (null bytes) and normalises to an absolute path before use.

import os


def safe_output_path(path):
    if path is None:
        return None

    if "\x00" in path:
        raise ValueError(f"Path contains a null byte, refusing to use: {path!r}")

    resolved = os.path.abspath(os.path.expanduser(path))
    return resolved