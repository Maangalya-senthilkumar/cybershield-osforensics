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
        else:
            if not _HAS_PYTSK3:
                raise RuntimeError("pytsk3 is not available and path is not a mounted directory")
            # attempt to open image with pytsk3
            try:
                self.img = pytsk3.Img_Info(path)
                # Use the first filesystem found.
                self.fs = pytsk3.FS_Info(self.img)
                self.mode = "tsk"
            except Exception as e:
                raise RuntimeError(f"Failed to open image with pytsk3: {e}")

    # Local helpers
    def _local_full(self, p: str) -> str:
        # normalize to remove leading /
        if p.startswith("/"):
            p = p[1:]
        return os.path.join(self.path, p)

    def exists(self, path: str) -> bool:
        if self.mode == "local":
            return os.path.exists(self._local_full(path))
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
