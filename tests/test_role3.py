import unittest
import tempfile
import os
import shutil
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestRole3SanitizationEngine(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.target_file = os.path.join(self.test_dir, "drive_block.bin")
        self.sample_bytes = b"SECRET_DRIVE_PATTERN_DATA" * 20
        
        with open(self.target_file, "wb") as f:
            f.write(self.sample_bytes)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def overwrite_zero_fill(self, file_path):
        if not os.path.exists(file_path):
            return False
        size = os.path.getsize(file_path)
        with open(file_path, "r+b") as f:
            f.write(b"\x00" * size)
        return True

    def overwrite_random_fill(self, file_path):
        if not os.path.exists(file_path):
            return False
        size = os.path.getsize(file_path)
        random_bytes = os.urandom(size)
        with open(file_path, "r+b") as f:
            f.write(random_bytes)
        return True

    def test_zero_fill_overwrite_verifies_byte_pattern(self):
        file_size = len(self.sample_bytes)
        success = self.overwrite_zero_fill(self.target_file)
        self.assertTrue(success)

        with open(self.target_file, "rb") as f:
            content = f.read()
            self.assertEqual(content, b"\x00" * file_size)

    def test_random_fill_overwrite_changes_content(self):
        success = self.overwrite_random_fill(self.target_file)
        self.assertTrue(success)

        with open(self.target_file, "rb") as f:
            content = f.read()
            self.assertNotEqual(content, self.sample_bytes)
            self.assertEqual(len(content), len(self.sample_bytes))

    def test_overwrite_non_existent_target(self):
        missing_path = os.path.join(self.test_dir, "non_existent_device.bin")
        self.assertFalse(self.overwrite_zero_fill(missing_path))

    def test_overwrite_empty_file_handling(self):
        empty_target = os.path.join(self.test_dir, "empty.bin")
        open(empty_target, "wb").close()

        success = self.overwrite_zero_fill(empty_target)
        self.assertTrue(success)
        self.assertEqual(os.path.getsize(empty_target), 0)


if __name__ == "__main__":
    unittest.main()