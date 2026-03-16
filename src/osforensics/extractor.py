"""Filesystem access and SleuthKit (pytsk3) wrapper.

This module exposes a FilesystemAccessor class that provides a small
uniform API for reading files and listing directories from either:
- a mounted directory on the host (fast, used during development), or
- a disk image via pytsk3 (Sleuth Kit Python bindings) when available.

The implementation is intentionally minimal — it provides the operations
we need for detection heuristics: exists(), read_file(), list_dir().
"""
from __future__ import annotations

import os
from typing import List, Optional

try:
    import pytsk3
    _HAS_PYTSK3 = True
except Exception:
    pytsk3 = None  # type: ignore
    _HAS_PYTSK3 = False


class FilesystemAccessor:
    """Uniform accessor for a filesystem snapshot.

    Two modes:
    - local: path points to a mounted directory on the host
    - tsk: path points to a disk image that will be opened with pytsk3
    """

    def __init__(self, path: str):
        self.path = path
        self.mode = "local"
        self.img = None
        self.fs = None

        if os.path.isdir(path):
            self.mode = "local"
        elif os.path.isfile(path):
             # It's a file but not a directory - check if it's a disk image or just a regular file
             if _HAS_PYTSK3:
                try:
                    self.img = pytsk3.Img_Info(path)
                    self.fs = pytsk3.FS_Info(self.img)
                    self.mode = "tsk"
                except Exception:
                    # Not a valid disk image, but it IS a local file.
                    # We treat the parent as the 'root' or just allow reading it if we had a better way.
                    # For now, most tools expect a directory root.
                    self.mode = "local_file"
                    self.path = path
             else:
                self.mode = "local_file"
                self.path = path
        else:
            if "*" in path:
                raise RuntimeError(f"Wildcards (*) are not supported in forensic paths: {path}")
            if not _HAS_PYTSK3:
                raise RuntimeError(f"Path does not exist and pytsk3 is not available: {path}")
            # attempt to open image with pytsk3
            try:
                self.img = pytsk3.Img_Info(path)
                # Use the first filesystem found.
                self.fs = pytsk3.FS_Info(self.img)
                self.mode = "tsk"
            except Exception as e:
                raise RuntimeError(f"Failed to open image with pytsk3 or path does not exist: {path}. Error: {e}")

    # Local helpers
    def _local_full(self, p: str) -> str:
        # normalize to remove leading /
        if p.startswith("/"):
            p = p[1:]
        return os.path.join(self.path, p)

    def exists(self, path: str) -> bool:
        if self.mode == "local":
            return os.path.exists(self._local_full(path))
        if self.mode == "local_file":
            # If they ask for "", it's the file. If they ask for the exact path or filename, it's the file.
            return path == "" or path == "/" or path == self.path or path == os.path.basename(self.path)
        # TSK mode
        try:
            self.fs.open(path)
            return True
        except Exception:
            return False

    def list_dir(self, path: str) -> List[str]:
        if self.mode == "local":
            full = self._local_full(path)
            try:
                return os.listdir(full)
            except OSError:
                return []
        if self.mode == "local_file":
            return [] # It's a file, not a dir
        # TSK mode
        try:
            dir_obj = self.fs.open_dir(path)
            names = []
            for entry in dir_obj:
                if not hasattr(entry, "info"):
                    continue
                name = entry.info.name.name.decode("utf-8", errors="ignore")
                if name in [".", ".."]:
                    continue
                names.append(name)
            return names
        except Exception:
            return []

    def read_file(self, path: str, max_bytes: Optional[int] = 10_000_000) -> Optional[bytes]:
        """Return raw bytes for the file at `path` or None if not found.

        For pytsk3, files are read via File object read_random.
        """
        if self.mode == "local":
            try:
                with open(self._local_full(path), "rb") as f:
                    return f.read(max_bytes)
            except Exception:
                return None
        
        if self.mode == "local_file":
            try:
                with open(self.path, "rb") as f:
                    return f.read(max_bytes)
            except Exception:
                return None

        try:
            f = self.fs.open(path)
            size = getattr(f.info, "meta", None)
            if size and size.size is not None:
                total = int(size.size)
            else:
                total = max_bytes
            to_read = min(total, max_bytes)
            return f.read_random(0, to_read)
        except Exception:
            return None
