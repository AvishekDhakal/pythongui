import unittest
from model import HashCrackerModel, DictionaryAttackThread
import os
import sqlite3

class TestHashCrackerModel(unittest.TestCase):
    def setUp(self):
        self.model = HashCrackerModel()

    def test_analyze_hash(self):
        # Test MD5 hash
        md5_hash = "098f6bcd4621d373cade4e832627b4f6"
        self.assertEqual(self.model.analyze_hash(md5_hash), "MD5")

        # Test SHA1 hash
        sha1_hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
        self.assertEqual(self.model.analyze_hash(sha1_hash), "SHA1")

        # Test SHA256 hash
        sha256_hash = "6dcd4ce23d88e2ee95838f7b014b6284ff8005e3b8d7ae0f900748fc2c3a4c64"
        self.assertEqual(self.model.analyze_hash(sha256_hash), "SHA256")

        # Test SHA512 hash
        sha512_hash = ("2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a19194"
                       "9ef3f4f6f0425a8811a638e104106f2a6e62ba057b813831431"
                       "f6a9f6e2a3a36e7a0673dbc8")
        self.assertEqual(self.model.analyze_hash(sha512_hash), "SHA512")

        # Test unknown hash
        unknown_hash = "abcdef"
        self.assertEqual(self.model.analyze_hash(unknown_hash), "Unknown")

    def test_export_to_file(self):
        hash = "098f6bcd4621d373cade4e832627b4f6"  # MD5 hash of 'test'
        password = 'test'
        self.model.export_to_file(hash, password)
        
        with open('output_file.txt', 'r') as f:
            data = f.read().strip()

        # Check if the file was written correctly
        self.assertEqual(data, "{\n  Hash: 098f6bcd4621d373cade4e832627b4f6 Password: test\n}")

    def tearDown(self):
        self.model.connection.close()
        os.remove('dictionary.txt')  # clean up the dictionary file
        os.remove('output_file.txt')  # clean up the output file

if __name__ == '__main__':
    unittest.main()