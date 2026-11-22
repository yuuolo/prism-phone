"""The background harness must reject owned release samples before any mutation."""
import runpy
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


class PreflightPassed(Exception):
    pass


class BackgroundPreflightTest(unittest.TestCase):
    def run_preflight(self, flags, avd="PrismAdvancedCI"):
        self.commands = []
        script = Path(__file__).resolve().parents[1] / "test-background.py"
        arguments = [str(script), "--adb", "adb", "--serial", "emulator-5564",
                     "--expected-avd", "PrismAdvancedCI", "--seed-apk", "unused",
                     "--client", "unused", "--ui-tool", "unused", "--output", "unused"]

        def command(argv, **kwargs):
            tail = argv[3:]
            self.commands.append(tail)
            if tail == ["emu", "avd", "name"]:
                output = avd + "\nOK\n"
            elif tail == ["shell", "dumpsys", "package", "dev.prism.android"]:
                output = flags
            elif tail == ["shell", "dumpsys", "deviceidle"]:
                # Stop before power inspection and fixture setup. No actual adb
                # call, APK install, force-stop or data reset may escape the mock.
                raise PreflightPassed()
            else:
                raise AssertionError("Unexpected command before safe preflight: " + repr(tail))
            return subprocess.CompletedProcess(argv, 0, stdout=output.encode(), stderr=b"")

        with patch.object(sys, "argv", arguments), patch("subprocess.run", side_effect=command):
            runpy.run_path(str(script), run_name="__main__")

    def test_release_sample_rejected_before_install_or_reset(self):
        with self.assertRaisesRegex(RuntimeError, "debuggable fixture"):
            self.run_preflight("    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]\n")

    def test_unrelated_debuggable_text_does_not_authorize_reset(self):
        with self.assertRaisesRegex(RuntimeError, "debuggable fixture"):
            self.run_preflight("component DEBUGGABLE\n    flags=[ HAS_CODE ]\n")

    def test_similar_flag_does_not_authorize_reset(self):
        with self.assertRaisesRegex(RuntimeError, "debuggable fixture"):
            self.run_preflight("    flags=[ NOT_DEBUGGABLE HAS_CODE ]\n")

    def test_missing_package_rejected_before_install_or_reset(self):
        with self.assertRaisesRegex(RuntimeError, "debuggable fixture"):
            self.run_preflight("Unable to find package: dev.prism.android\n")

    def test_wrong_avd_rejected_before_package_or_power_commands(self):
        with self.assertRaisesRegex(RuntimeError, "AVD identity differs"):
            self.run_preflight("    flags=[ DEBUGGABLE HAS_CODE ]\n", "PrismInstallerCI")
        self.assertEqual([["emu", "avd", "name"]], self.commands)

    def test_actual_debug_flag_reaches_readonly_power_preflight(self):
        with self.assertRaises(PreflightPassed):
            self.run_preflight("    flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]\n")


if __name__ == "__main__":
    unittest.main()
