"""
unpacker.py — APKUnpacker class: extracts an APK as a ZIP archive, then runs apktool
and jadx to produce three analysis-ready directory layouts.
"""

import shutil
import subprocess
import zipfile
from pathlib import Path

import config


class APKUnpacker:
    """
    Manages extraction and decompilation of a single APK file.

    Creates three output directories under workspace/{scan_id}/:
      raw/      — APK extracted as a plain ZIP (classes.dex, res/, assets/, etc.)
      apktool/  — apktool output: AndroidManifest.xml decoded, smali code, res/
      jadx/     — jadx output: Java source code reconstructed from bytecode
    """

    def __init__(self, apk_path: str, scan_id: str):
        """
        Prepares the unpacker.
        Raises FileNotFoundError immediately if the APK file does not exist.
        """
        self.apk_path = Path(apk_path)
        self.scan_id  = scan_id

        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK not found: {self.apk_path}")

        self.scan_workspace = config.WORKSPACE_DIR / scan_id
        self.raw_dir        = self.scan_workspace / "raw"
        self.apktool_dir    = self.scan_workspace / "apktool"
        self.jadx_dir       = self.scan_workspace / "jadx"

    def unpack(self) -> dict:
        """
        Runs all three extraction steps in sequence.

        Returns a dict with string paths for each directory plus an errors list.
        Never raises — each step is wrapped independently; failures go into errors[].
        """
        errors = []

        print(f"\n[*] Unpacking APK  : {self.apk_path.name}")
        print(f"    Scan workspace : {self.scan_workspace}")

        # ── Step 1: ZIP extraction ─────────────────────────────────────────────
        try:
            self._extract_zip()
            print(f"    [OK]   ZIP extracted  → {self.raw_dir}")
        except Exception as exc:
            msg = f"ZIP extraction failed: {exc}"
            errors.append(msg)
            print(f"    [FAIL] {msg}")

        # ── Step 2: apktool ───────────────────────────────────────────────────
        try:
            self._run_apktool()
            print(f"    [OK]   apktool done   → {self.apktool_dir}")
        except Exception as exc:
            msg = f"apktool failed: {exc}"
            errors.append(msg)
            print(f"    [FAIL] {msg}")

        # ── Step 3: jadx ─────────────────────────────────────────────────────
        try:
            self._run_jadx()
            print(f"    [OK]   jadx done      → {self.jadx_dir}")
        except Exception as exc:
            msg = f"jadx failed: {exc}"
            errors.append(msg)
            print(f"    [FAIL] {msg}")

        return {
            "scan_workspace": str(self.scan_workspace),
            "raw_dir":        str(self.raw_dir),
            "apktool_dir":    str(self.apktool_dir),
            "jadx_dir":       str(self.jadx_dir),
            "errors":         errors,
        }

    def _extract_zip(self):
        """
        Deletes raw_dir if it already exists, then extracts the APK as a ZIP archive.
        APK files are valid ZIP files containing the compiled app assets.
        """
        if self.raw_dir.exists():
            shutil.rmtree(self.raw_dir)
        self.raw_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(self.apk_path, "r") as zip_ref:
            zip_ref.extractall(self.raw_dir)

    def _run_apktool(self):
        """
        Runs apktool to decode resources and manifest into human-readable form.
        The -f flag forces overwrite of an existing output directory.
        Raises RuntimeError with stderr content if apktool exits non-zero.
        """
        command = [
            config.APKTOOL_PATH,
            "d", str(self.apk_path),
            "-o", str(self.apktool_dir),
            "-f",
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "apktool exited with a non-zero code")

    def _run_jadx(self):
        """
        Runs jadx to decompile bytecode into Java source files.

        jadx frequently exits with return code 1 even on a successful decompile,
        so we do NOT check the return code. Instead we verify that the output
        directory was created and contains at least one file.
        """
        self.jadx_dir.mkdir(parents=True, exist_ok=True)

        command = [
            config.JADX_PATH,
            str(self.apk_path),
            "-d", str(self.jadx_dir),
            "--no-res",
            "--show-bad-code",
        ]
        subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
        )

        all_files = list(self.jadx_dir.rglob("*"))
        if not any(f.is_file() for f in all_files):
            raise RuntimeError(
                "jadx produced no output files — the decompile may have failed silently."
            )

    def cleanup(self):
        """
        Silently deletes the entire scan workspace directory.
        Used to free disk space after a scan result has been saved.
        """
        try:
            if self.scan_workspace.exists():
                shutil.rmtree(self.scan_workspace)
        except Exception:
            pass
