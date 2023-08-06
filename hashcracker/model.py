


from PyQt5.QtCore import QRunnable
from queue import Queue
from PyQt5.QtCore import QThread, pyqtSignal
import hashlib
import os
import sqlite3

class HashCrackerModel:
    def __init__(self):
        self.algorithms = {
            'MD5': hashlib.md5,
            'SHA1': hashlib.sha1,
            'SHA256': hashlib.sha256,
            'SHA512': hashlib.sha512
        }
         # Create a connection to the SQLite database
        # If the database doesn't exist, it will be created
        self.connection = sqlite3.connect('hashes.db')
        # Create a cursor
        self.cursor = self.connection.cursor()
        # Create the table if it doesn't exist
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS hashes (
                hash TEXT,
                password TEXT
            )
        ''')
        self.connection.commit()
    def analyze_hash(self, hash):
        hash_length = len(hash)
        if hash_length == 32:  # MD5
            return 'MD5'
        elif hash_length == 40:  # SHA1
            return 'SHA1'
        elif hash_length == 64:  # SHA256
            return 'SHA256'
        elif hash_length == 128:  # SHA512
            return 'SHA512'
        else:
            return 'Unknown'


    def crack_hash(self, hash, hash_type, attack_mode, dictionary_file_path, queue):
        algorithm = self.algorithms.get(hash_type, None)
        if algorithm is None:
            raise ValueError(f"Unknown hash type: {hash_type}")
        if attack_mode == "Dictionary Attack":
            thread = DictionaryAttackThread(hash, algorithm, dictionary_file_path, queue)
            return thread
        else:
            raise ValueError(f"Unknown attack mode: {attack_mode}")

    def save_to_db(self, hash: str, password: str):
        try:
            self.cursor.execute("INSERT INTO hashes VALUES (?, ?)", (hash, password))
            self.connection.commit()
        except Exception as e:
            print(f"Error while saving to the database: {e}")
    
    def close_db(self):
        self.connection.close()

    def export_to_file(self, hash: str, password: str):
        with open('output_file.txt', 'a') as f:
            f.write(f'{{{hash} {password}}}\n')  # updated format

class DictionaryAttackThread(QRunnable):
    password_cracked = pyqtSignal(str, str)  # updated signal

    def __init__(self, hash, algorithm, dictionary_file_path,queue: Queue):
        super().__init__()
        self.hash = hash
        self.algorithm = algorithm
        self.dictionary_file_path = dictionary_file_path
        self.queue = queue


    def run(self):
        try:
            with open(self.dictionary_file_path, 'r') as f:
                for line in f:
                    word = line.strip()
                    if self.algorithm(word.encode()).hexdigest() == self.hash:
                        self.queue.put((self.hash, word))  # put the result on the queue
                        return
        except Exception as e:
            print("Error in DictionaryAttackThread: ", str(e))
            self.queue.put((self.hash, None))  # put an error result on the queue