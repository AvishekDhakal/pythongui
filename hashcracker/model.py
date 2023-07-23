# # model.py
# import hashlib
# import itertools
# import sqlite3
# import string
# import bisect
# from typing import Optional
# from PyQt5.QtCore import QThread, pyqtSignal



# class HashCrackerModel:
#     def __init__(self):
#         self.connection = sqlite3.connect('hashes.db')
#         self.cursor = self.connection.cursor()
#         self.cursor.execute("""
#             CREATE TABLE IF NOT EXISTS hashes (
#                 hash TEXT,
#                 password TEXT
#             )
#         """)
#         self.connection.commit()
#         self.character_set = string.ascii_letters + string.digits
#         self.cache = {}  # Cache for previously cracked hashes

#     def crack_hash(self, hash: str, hash_type: str, attack_mode: str, dictionary_file: Optional[str] = None) -> Optional[str]:
#         if hash in self.cache:
#             return self.cache[hash]

#         if attack_mode == "Brute Force":
#             brute_force_thread = BruteForceThread(hash, hash_type, self.character_set)
#             return brute_force_thread
#         elif attack_mode == "Dictionary Attack":
#             if dictionary_file is not None:
#                 return self.dictionary_attack(hash, hash_type, dictionary_file)
#             else:
#                 return None
#         else:
#             raise ValueError("Invalid attack mode")

#     def dictionary_attack(self, hash: str, hash_type: str, dictionary_file: str) -> Optional[str]:
#         with open(dictionary_file, 'r') as f:
#             words = f.read().splitlines()
#         words.sort()  # Sort the words for binary search
#         for word in words:
#             if hashlib.new(hash_type, word.encode()).hexdigest() == hash:
#                 return word
#         return None

#     def save_to_db(self, hash: str, password: str):
#         self.cursor.execute("INSERT INTO hashes VALUES (?, ?)", (hash, password))
#         self.connection.commit()

#     def export_to_file(self, hash: str, password: str):
#         with open('cracked_hashes.txt', 'a') as f:  # Appends to the file (doesn't overwrite)
#             f.write(f'Hash: {hash}\nPassword: {password}\n')


# model.py

# from PyQt5.QtCore import QThread, pyqtSignal
# import hashlib
# import os

# class HashCrackerModel:
#     def __init__(self):
#         self.algorithms = {
#             'MD5': hashlib.md5,
#             'SHA1': hashlib.sha1,
#             'SHA256': hashlib.sha256,
#             'SHA512': hashlib.sha512
#         }

#     def crack_hash(self, hash, hash_type, attack_mode, dictionary_file_path):
#         algorithm = self.algorithms.get(hash_type, None)
#         if algorithm is None:
#             raise ValueError(f"Unknown hash type: {hash_type}")
#         if attack_mode == "Dictionary Attack":
#             return DictionaryAttackThread(hash, algorithm, dictionary_file_path)
#         else:
#             raise ValueError(f"Unknown attack mode: {attack_mode}")

#     def save_to_db(self, hash: str, password: str):
#         self.cursor.execute("INSERT INTO hashes VALUES (?, ?)", (hash, password))
#         self.connection.commit()

#     def export_to_file(self, hash: str, password: str):
#         with open('cracked_hashes.txt', 'a') as f:  # Appends to the file (doesn't overwrite)
#             f.write(f'Hash: {hash}\nPassword: {password}\n')

# class DictionaryAttackThread(QThread):
#     password_cracked = pyqtSignal(str)

#     def __init__(self, hash, algorithm, dictionary_file_path):
#         super().__init__()
#         self.hash = hash
#         self.algorithm = algorithm
#         self.dictionary_file_path = dictionary_file_path

#     def run(self):
#         try:
#             with open(self.dictionary_file_path, 'r') as f:
#                 for line in f:
#                     word = line.strip()
#                     if self.algorithm(word.encode()).hexdigest() == self.hash:
#                         self.password_cracked.emit(word)
#                         return
#         except Exception as e:
#             print("Error in DictionaryAttackThread: ", str(e))
#             self.password_cracked.emit(None)



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

    def crack_hash(self, hash, hash_type, attack_mode, dictionary_file_path):
        algorithm = self.algorithms.get(hash_type, None)
        if algorithm is None:
            raise ValueError(f"Unknown hash type: {hash_type}")
        if attack_mode == "Dictionary Attack":
            thread = DictionaryAttackThread(hash, algorithm, dictionary_file_path)
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

class DictionaryAttackThread(QThread):
    password_cracked = pyqtSignal(str, str)  # updated signal

    def __init__(self, hash, algorithm, dictionary_file_path):
        super().__init__()
        self.hash = hash
        self.algorithm = algorithm
        self.dictionary_file_path = dictionary_file_path

    def run(self):
        try:
            with open(self.dictionary_file_path, 'r') as f:
                for line in f:
                    word = line.strip()
                    if self.algorithm(word.encode()).hexdigest() == self.hash:
                        self.password_cracked.emit(self.hash, word)
                        return
        except Exception as e:
            print("Error in DictionaryAttackThread: ", str(e))
            self.password_cracked.emit(self.hash, None)