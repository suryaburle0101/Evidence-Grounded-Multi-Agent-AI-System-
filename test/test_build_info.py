import subprocess
import unittest
from unittest.mock import patch

from pipeline import build_info


class BuildInfoTests(unittest.TestCase):
    def test_short_hash_is_cached_clean_or_marked_dirty(self):
        clean = [
            subprocess.CompletedProcess([], 0, stdout="abc1234\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
        with patch.object(build_info.subprocess, "run", side_effect=clean) as run:
            self.assertEqual(build_info._git_commit_hash(), "abc1234")
        self.assertEqual(run.call_args_list[0].args[0][-3:], ["rev-parse", "--short", "HEAD"])
        self.assertEqual(run.call_args_list[1].args[0][-2:], ["status", "--porcelain"])

        dirty = [
            subprocess.CompletedProcess([], 0, stdout="abc1234\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=" M file.py\n", stderr=""),
        ]
        with patch.object(build_info.subprocess, "run", side_effect=dirty):
            self.assertEqual(build_info._git_commit_hash(), "abc1234 (dirty)")

    def test_git_unavailable_returns_no_git(self):
        with patch.object(build_info.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(build_info._git_commit_hash(), "no-git")


if __name__ == "__main__":
    unittest.main()
