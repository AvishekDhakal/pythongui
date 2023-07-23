import unittest
from model import HashCrackerModel, DictionaryAttackThread
import os

class TestHashCrackerModel(unittest.TestCase):
    def setUp(self):
        self.model = HashCrackerModel()

    def test_crack_hash(self):
        hash = '098f6bcd4621d373cade4e832627b4f6'  # MD5 hash of 'test'
        hash_type = 'MD5'
        attack_mode = 'Dictionary Attack'
        dictionary_file_path = 'dictionary.txt'  # replace this with the path to your dictionary file

        # Write 'test' to the dictionary file
        with open(dictionary_file_path, 'w') as f:
            f.write('test\n')

        thread = self.model.crack_hash(hash, hash_type, attack_mode, dictionary_file_path)
        thread.start()
        thread.wait()

        self.assertEqual(thread.result, 'test')  # check the computed result

    def test_save_to_db(self):
        hash = '098f6bcd4621d373cade4e832627b4f6'  # MD5 hash of 'test'
        password = 'test'
        self.model.save_to_db(hash, password)

        self.model.cursor.execute('SELECT * FROM hashes')
        data = self.model.cursor.fetchone()

        self.assertEqual(data, (hash, password))  # check the saved data

    def tearDown(self):
        self.model.close_db()
        os.remove('dictionary.txt')  # clean up the dictionary file

if __name__ == '__main__':
    unittest.main()