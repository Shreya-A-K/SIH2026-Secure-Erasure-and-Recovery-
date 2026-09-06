"""
recovery_engine.py
Person 5 — Forensics/Recovery module

Wraps three recovery backends behind one interface:
  1. pytsk3   -> filesystem-aware recovery (walks MFT/inode table, finds
                 deleted-but-unallocated entries with intact metadata)
  2. Scalpel  -> signature-based file carving (config-driven, fast)
  3. Foremost -> signature-based file carving (built-in signatures, good fallback)

Output of every backend is normalized into RecoveredFile so downstream
modules (confidence_score.py, post_wipe_validation.py, Person 6's
Assurance/Report layer) don't care which engine produced a hit.
"""

import os
import subprocess
import hashlib
import shutil
import dataclasses
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime, timezone

try:
    import pytsk3
except ImportError:
    pytsk3 = None  # allow module import even if pytsk3 isn't installed yet


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class RecoveredFile:
    name: str
    method: str                 # "pytsk3" | "scalpel" | "foremost"
    out_path: str                # where the recovered bytes were written
    recovered_size: int
    expected_size: Optional[int] = None   # from filesystem metadata, if known
    inode: Optional[int] = None
    file_type: Optional[str] = None       # extension / signature match
    metadata_intact: bool = False         # MFT/inode entry still present & valid
    fragmented: bool = False
    sha256: str = ""
    recovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def compute_hash(self):
        h = hashlib.sha256()
        with open(self.out_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        self.sha256 = h.hexdigest()
        return self.sha256

    def as_dict(self):
        return dataclasses.asdict(self)


class RecoveryError(Exception):
    pass


# --------------------------------------------------------------------------
# 1. pytsk3 — filesystem-aware recovery
# --------------------------------------------------------------------------

class TSKRecovery:
    """Walks a device/image's filesystem for deleted-but-recoverable entries."""

    def __init__(self, device_path: str, out_dir: str):
        if pytsk3 is None:
            raise RecoveryError("pytsk3 is not installed in this environment")
        self.device_path = device_path
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.img = pytsk3.Img_Info(device_path)

    def _open_fs(self, offset_bytes: int = 0) -> "pytsk3.FS_Info":
        try:
            return pytsk3.FS_Info(self.img, offset=offset_bytes)
        except Exception as e:
            raise RecoveryError(f"Could not open filesystem at offset {offset_bytes}: {e}")

    def find_partitions(self):
        """Return list of (offset_bytes, description). Falls back to a single
        offset-0 'partition' if no volume system is found (e.g. plain USB)."""
        try:
            vol = pytsk3.Volume_Info(self.img)
            parts = []
            for p in vol:
                if p.len > 0 and "Unallocated" not in p.desc.decode(errors="ignore"):
                    parts.append((p.start * 512, p.desc.decode(errors="ignore")))
            if parts:
                return parts
        except Exception:
            pass
        return [(0, "no partition table / raw filesystem")]

    def _is_deleted(self, f) -> bool:
        meta = f.info.meta
        if meta is None:
            return False
        # NTFS/FAT/EXT: unallocated flag on the meta entry
        return int(meta.flags) & pytsk3.TSK_FS_META_FLAG_UNALLOC != 0

    def walk_deleted(self, fs, directory=None, path="/", _depth=0, max_depth=15):
        """Recursively yield deleted file entries with recoverable content."""
        if directory is None:
            directory = fs.open_dir(path="/")
        if _depth > max_depth:
            return
        for entry in directory:
            try:
                name = entry.info.name.name.decode(errors="ignore")
            except Exception:
                continue
            if name in (".", ".."):
                continue
            try:
                is_dir = entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
            except Exception:
                is_dir = False

            if is_dir and not self._is_deleted(entry):
                # only recurse into still-allocated directories; a deleted
                # directory's children are usually orphaned and picked up
                # by inode-table scan instead
                try:
                    sub = entry.as_directory()
                    yield from self.walk_deleted(fs, sub, path + name + "/", _depth + 1, max_depth)
                except Exception:
                    continue
            elif self._is_deleted(entry) and entry.info.meta and entry.info.meta.size > 0:
                yield (path + name, entry)

    def recover_entry(self, fs_entry, dest_name: str) -> Optional[RecoveredFile]:
        meta = fs_entry.info.meta
        expected_size = int(meta.size)
        out_path = os.path.join(self.out_dir, "tsk_" + dest_name.strip("/").replace("/", "_"))

        try:
            written = 0
            with open(out_path, "wb") as out:
                offset = 0
                BUF = 1 << 20
                while offset < expected_size:
                    to_read = min(BUF, expected_size - offset)
                    data = fs_entry.read_random(offset, to_read)
                    if not data:
                        break
                    out.write(data)
                    written += len(data)
                    offset += len(data)
        except Exception:
            if os.path.exists(out_path) and os.path.getsize(out_path) == 0:
                os.remove(out_path)
                return None

        if written == 0:
            if os.path.exists(out_path):
                os.remove(out_path)
            return None

        rf = RecoveredFile(
            name=os.path.basename(dest_name),
            method="pytsk3",
            out_path=out_path,
            recovered_size=written,
            expected_size=expected_size,
            inode=int(meta.addr),
            file_type=os.path.splitext(os.path.basename(dest_name))[1].lstrip('.').lower(),
            metadata_intact=True,
            fragmented=(written < expected_size),
        )
        rf.compute_hash()
        return rf

    def run(self) -> List[RecoveredFile]:
        results = []
        for offset, desc in self.find_partitions():
            try:
                fs = self._open_fs(offset)
            except RecoveryError:
                continue
            for path, entry in self.walk_deleted(fs):
                rf = self.recover_entry(entry, path)
                if rf:
                    results.append(rf)
        return results


# --------------------------------------------------------------------------
# 2 & 3. Scalpel / Foremost — signature-based carving
# --------------------------------------------------------------------------

class CarvingRecovery:
    """Thin subprocess wrapper shared by Scalpel and Foremost."""

    def __init__(self, device_path: str, out_dir: str):
        self.device_path = device_path
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)

    def _check_binary(self, name: str):
        if shutil.which(name) is None:
            raise RecoveryError(f"'{name}' not found on PATH — check install step")

    def run_scalpel(self, config_path: Optional[str] = None) -> List[RecoveredFile]:
        self._check_binary("scalpel")
        out_subdir = os.path.join(self.out_dir, "scalpel_out")
        if os.path.exists(out_subdir):
            shutil.rmtree(out_subdir)
        cmd = ["scalpel", self.device_path, "-o", out_subdir]
        if config_path:
            cmd += ["-c", config_path]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return self._collect_carved(out_subdir, "scalpel")

    def run_foremost(self) -> List[RecoveredFile]:
        self._check_binary("foremost")
        out_subdir = os.path.join(self.out_dir, "foremost_out")
        if os.path.exists(out_subdir):
            shutil.rmtree(out_subdir)
        os.makedirs(out_subdir, exist_ok=True)
        cmd = ["foremost", "-i", self.device_path, "-o", out_subdir]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return self._collect_carved(out_subdir, "foremost")

    def _collect_carved(self, out_subdir: str, method: str) -> List[RecoveredFile]:
        results = []
        for root, _, files in os.walk(out_subdir):
            for fname in files:
                if fname.lower() in ("audit.txt",):
                    continue
                full_path = os.path.join(root, fname)
                size = os.path.getsize(full_path)
                if size == 0:
                    continue
                rf = RecoveredFile(
                    name=fname,
                    method=method,
                    out_path=full_path,
                    recovered_size=size,
                    expected_size=None,       # carving has no filesystem metadata
                    metadata_intact=False,    # signature-based = no MFT/inode info
                    file_type=os.path.splitext(fname)[1].lstrip("."),
                    fragmented=False,         # unknown without metadata; conservative default
                )
                rf.compute_hash()
                results.append(rf)
        return results


# --------------------------------------------------------------------------
# Unified entry point
# --------------------------------------------------------------------------

def run_full_recovery(device_path: str, out_dir: str,
                       use_tsk=True, use_scalpel=True, use_foremost=True,
                       scalpel_config: Optional[str] = None) -> List[RecoveredFile]:
    """Run all requested engines and return a merged, deduped-by-hash list."""
    all_results: List[RecoveredFile] = []

    if use_tsk:
        try:
            all_results += TSKRecovery(device_path, os.path.join(out_dir, "tsk")).run()
        except RecoveryError as e:
            print(f"[recovery_engine] TSK skipped: {e}")

    carver = CarvingRecovery(device_path, out_dir)
    if use_scalpel:
        try:
            all_results += carver.run_scalpel(scalpel_config)
        except (RecoveryError, subprocess.CalledProcessError) as e:
            print(f"[recovery_engine] Scalpel skipped: {e}")
    if use_foremost:
        try:
            all_results += carver.run_foremost()
        except (RecoveryError, subprocess.CalledProcessError) as e:
            print(f"[recovery_engine] Foremost skipped: {e}")

    # dedupe: same sha256 recovered by two engines -> keep the higher-fidelity one
    # (pytsk3 has metadata, so it wins over carving on a hash collision)
    priority = {"pytsk3": 0, "scalpel": 1, "foremost": 2}
    best_by_hash = {}
    for rf in all_results:
        if not rf.sha256:
            continue
        existing = best_by_hash.get(rf.sha256)
        if existing is None or priority[rf.method] < priority[existing.method]:
            best_by_hash[rf.sha256] = rf
    return list(best_by_hash.values())
