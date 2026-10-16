#!/usr/bin/env python3
# Copyright (c) 2026 The Peercoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test static app/ZIP deployment without optional DMG dependencies.

Run with: python3 contrib/macdeploy/test_macdeployqtplus.py
Mach-O inspection is mocked so these tests can also run on Linux.
"""

import builtins
import contextlib
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SCRIPT = Path(__file__).resolve().with_name("macdeployqtplus")


class DeployTest(unittest.TestCase):
    def test_static_bundle_without_dmg_modules(self):
        for make_zip in (False, True):
            with self.subTest(zip=make_zip), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                bundle = root / "Peercoin-Qt.app"
                binary = bundle / "Contents/MacOS/Peercoin-Qt"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"mock static Mach-O binary")
                (bundle / "Contents/Resources").mkdir()
                translations = root / "translations"
                translations.mkdir()
                (translations / "qt_en.qm").write_bytes(b"mock translation")
                argv = [str(SCRIPT), str(bundle), "-no-plugins", "-no-strip",
                        "-translations-dir", str(translations)]
                if make_zip:
                    argv += ["-zip", "peercoin-test"]

                original_import = builtins.__import__

                def without_dmg_modules(name, *args, **kwargs):
                    if name in ("ds_store", "mac_alias"):
                        raise ModuleNotFoundError(name)
                    return original_import(name, *args, **kwargs)

                def inspect_binary(command, **kwargs):
                    self.assertTrue("-L" in command or "--dylibs-used" in command)
                    return subprocess.CompletedProcess(command, 0, f"{command[-1]}:\n", "")

                previous_cwd = Path.cwd()
                try:
                    os.chdir(root)
                    with patch.object(sys, "argv", argv), \
                            patch("builtins.__import__", side_effect=without_dmg_modules), \
                            patch("subprocess.run", side_effect=inspect_binary), \
                            patch("platform.system", return_value="Linux"), \
                            contextlib.redirect_stdout(io.StringIO()), \
                            contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as result:
                            runpy.run_path(str(SCRIPT), run_name="__main__")
                        self.assertEqual(result.exception.code, 0)
                    deployed = root / "dist/Peercoin-Qt.app/Contents"
                    self.assertEqual((deployed / "MacOS/Peercoin-Qt").read_bytes(), binary.read_bytes())
                    self.assertTrue((deployed / "Resources/qt.conf").exists())
                    self.assertTrue((deployed / "Resources/qt_en.qm").exists())
                    if make_zip:
                        with zipfile.ZipFile(root / "peercoin-test.zip") as archive:
                            self.assertIn("Peercoin-Qt.app/Contents/MacOS/Peercoin-Qt", archive.namelist())
                finally:
                    os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()
