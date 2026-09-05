import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestRole5Forensics(unittest.TestCase):

    def calculate_confidence_score(self, matched_header, bytes_recovered, total_bytes):
        if total_bytes == 0:
            return 0.0
        
        base_score = 50.0 if matched_header else 0.0
        integrity_score = (bytes_recovered / total_bytes) * 50.0
        return round(base_score + integrity_score, 2)

    def detect_file_type(self, raw_bytes):
        signatures = {
            b"\x89PNG\r\n\x1a\n": "PNG",
            b"%PDF": "PDF",
            b"PK\x03\x04": "ZIP/DOCX"
        }
        for sig, file_type in signatures.items():
            if raw_bytes.startswith(sig):
                return file_type
        return "UNKNOWN"

    def test_confidence_score_zero_after_complete_wipe(self):
        score = self.calculate_confidence_score(matched_header=False, bytes_recovered=0, total_bytes=1024)
        self.assertEqual(score, 0.0)

    def test_confidence_score_max_for_intact_recovered_file(self):
        score = self.calculate_confidence_score(matched_header=True, bytes_recovered=1024, total_bytes=1024)
        self.assertEqual(score, 100.0)

    def test_confidence_score_partial_recovery(self):
        score = self.calculate_confidence_score(matched_header=True, bytes_recovered=512, total_bytes=1024)
        self.assertEqual(score, 75.0)

    def test_file_carving_detects_png_header(self):
        buffer = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR..."
        file_type = self.detect_file_type(buffer)
        self.assertEqual(file_type, "PNG")

    def test_file_carving_detects_pdf_header(self):
        buffer = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n..."
        file_type = self.detect_file_type(buffer)
        self.assertEqual(file_type, "PDF")

    def test_file_carving_unknown_pattern(self):
        buffer = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        file_type = self.detect_file_type(buffer)
        self.assertEqual(file_type, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()