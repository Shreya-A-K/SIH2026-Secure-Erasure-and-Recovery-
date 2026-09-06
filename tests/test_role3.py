import unittest
import tempfile
import os
import shutil
import sys

# Ensure root directory is in the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sanitization_engine import SanitizationEngine


class TestRole3SanitizationEngine(unittest.TestCase):

    def setUp(self):
        self.engine = SanitizationEngine()
        self.test_dir = tempfile.mkdtemp()
        self.target_file = os.path.join(self.test_dir, "drive_block.txt")
        self.sample_bytes = b"SECRET_DRIVE_PATTERN_DATA" * 20
        
        with open(self.target_file, "wb") as f:
            f.write(self.sample_bytes)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    # -------------------------------------------------------------------------
    # Sanitization Engine Method Tests
    # -------------------------------------------------------------------------

    def test_zero_fill_overwrite_verifies_byte_pattern(self):
        file_size = len(self.sample_bytes)
        res = self.engine.overwrite_file(self.target_file, skip_prompt=True)
        
        self.assertEqual(res["status"], "SUCCESS")

        with open(self.target_file, "rb") as f:
            content = f.read()
            self.assertEqual(content, b"\x00" * file_size)

    def test_random_fill_overwrite_changes_content(self):
        res = self.engine.overwrite_file(self.target_file, skip_prompt=True)
        
        self.assertEqual(res["status"], "SUCCESS")

        with open(self.target_file, "rb") as f:
            content = f.read()
            self.assertNotEqual(content, self.sample_bytes)

    def test_overwrite_non_existent_target(self):
        missing_path = os.path.join(self.test_dir, "non_existent_device.txt")
        res = self.engine.overwrite_file(missing_path, skip_prompt=True)
        
        self.assertEqual(res["status"], "FAILURE")
        self.assertEqual(res["message"], "File does not exist")

    def test_overwrite_empty_file_handling(self):
        empty_target = os.path.join(self.test_dir, "empty.txt")
        open(empty_target, "wb").close()

        res = self.engine.overwrite_file(empty_target, skip_prompt=True)
        
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(os.path.getsize(empty_target), 0)


if __name__ == "__main__":
    unittest.main()