from PyQt5.QtCore import QRunnable
from queue import Queue
from PyQt5.QtCore import pyqtSignal
import hashlib
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
        """
        The function `analyze_hash` takes a hash as input and returns the type of hash (MD5, SHA1,
        SHA256, SHA512) based on its length.
        
        :param hash: The "hash" parameter is a string that represents a cryptographic hash value
        :return: the type of hash algorithm based on the length of the input hash. If the length is 32,
        it returns 'MD5'. If the length is 40, it returns 'SHA1'. If the length is 64, it returns
        'SHA256'. If the length is 128, it returns 'SHA512'. If the length does not match any of these
        values
        """
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
        """
        The function `crack_hash` takes in a hash, hash type, attack mode, dictionary file path, and a
        queue, and returns a thread object based on the attack mode.
        
        :param hash: The `hash` parameter is the hash value that you want to crack. It is the encrypted
        representation of the original data
        :param hash_type: The `hash_type` parameter specifies the type of hash algorithm used to
        generate the hash. Examples of hash types include MD5, SHA1, SHA256, etc
        :param attack_mode: The `attack_mode` parameter specifies the type of attack to be performed on
        the hash. In this code snippet, the two supported attack modes are "Dictionary Attack" and an
        unknown attack mode
        :param dictionary_file_path: The `dictionary_file_path` parameter is the file path to the
        dictionary file that contains a list of words or passwords that will be used for the dictionary
        attack
        :param queue: The "queue" parameter is a queue object that is used to store the results of the
        cracking process. It allows multiple threads or processes to add results to the queue, which can
        then be processed or displayed later
        :return: The code is returning an instance of the `DictionaryAttackThread` class.
        """
        algorithm = self.algorithms.get(hash_type, None)
        if algorithm is None:
            raise ValueError(f"Unknown hash type: {hash_type}")
        if attack_mode == "Dictionary Attack":
            thread = DictionaryAttackThread(hash, algorithm, dictionary_file_path, queue)
            return thread
        else:
            raise ValueError(f"Unknown attack mode: {attack_mode}")

    def save_to_db(self, hash: str, password: str):
        """
        The function saves a hash and password to a database table.
        
        :param hash: The `hash` parameter is a string that represents the hash value of a password. It
        is typically generated using a hashing algorithm like MD5, SHA-1, or bcrypt. The purpose of
        storing the hash value instead of the actual password is to enhance security, as it makes it
        more difficult for
        :type hash: str
        :param password: The `password` parameter is a string that represents the password that you want
        to save to the database
        :type password: str
        """
        
        try:
            self.cursor.execute("INSERT INTO hashes VALUES (?, ?)", (hash, password))
            self.connection.commit()
        except Exception as e:
            print(f"Error while saving to the database: {e}")
    
    def close_db(self):
        """
        The close_db function is used to close the database connection.
        """
        self.connection.close()

    def export_to_file(self, hash: str, password: str):
        """
        The function exports a hash and password to a file in a specific format.
        
        :param hash: The `hash` parameter is a string that represents a hash value. It is typically used
        in cryptography to represent a fixed-size string of characters that is generated by applying a
        hash function to some input data
        :type hash: str
        :param password: The `password` parameter is a string that represents the password associated
        with the given hash
        :type password: str
        """
        with open('output_file.txt', 'a') as f:
            f.write(f'{{{hash} {password}}}\n')  

class DictionaryAttackThread(QRunnable):
    password_cracked = pyqtSignal(str, str)  # updated signal

    def __init__(self, hash, algorithm, dictionary_file_path,queue: Queue):
        super().__init__()
        self.hash = hash
        self.algorithm = algorithm
        self.dictionary_file_path = dictionary_file_path
        self.queue = queue


    def run(self):
        """
        The function reads a dictionary file, hashes each word using a specified algorithm, and checks
        if the hash matches a given target hash, returning the result on a queue.
        :return: The result of the dictionary attack is being returned. If a word is found in the
        dictionary that matches the hash, it is put on the queue along with the hash. If no match is
        found or an error occurs, None is put on the queue along with the hash.
        """
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