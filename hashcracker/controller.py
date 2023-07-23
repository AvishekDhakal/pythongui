





from model import HashCrackerModel, DictionaryAttackThread
from PyQt5.QtWidgets import QFileDialog, QMessageBox
import os
import re

class HashCrackerController:
    def __init__(self, view):
        self.view = view
        self.model = HashCrackerModel()
        self.dictionary_file_path = None
        self.threads = []  # to keep track of threads
        current_directory = os.getcwd()
        self.output_file_path = os.path.join(current_directory, "output_file.txt")

    def analyze_hash(self):
        hash = self.view.hash_analyze_input.text().strip()
        hash_type = self.model.analyze_hash(hash)  # We need to implement this method in the model
        QMessageBox.information(self.view, "Hash Type", f"The analyzed hash type is: {hash_type}")

    def upload_hash_file(self):
        self.hash_file_path, _ = QFileDialog.getOpenFileName(self.view, "Open Hash File", "", "Text Files (*.txt)")
        if self.hash_file_path:
            self.view.hash_input.setText(self.hash_file_path)

    def upload_dictionary_file(self):
        self.dictionary_file_path, _ = QFileDialog.getOpenFileName(self.view, "Open Dictionary File", "", "Text Files (*.txt)")
        if self.dictionary_file_path:
            if os.path.isfile(self.dictionary_file_path):
                QMessageBox.information(self.view, "Dictionary File Upload", f"Dictionary file successfully uploaded from {self.dictionary_file_path}")
            else:
                QMessageBox.warning(self.view, "File Error", "The selected dictionary file could not be found.")

    # def start_cracking(self):
    #     hash_type = self.view.hash_type.currentText()

    #     # Check if the hash input is a file path
    #     hash_input = self.view.hash_input.text().strip()
    #     if os.path.isfile(hash_input):
    #         with open(hash_input, 'r') as file:
    #             hash_input = file.read().strip()

    #     # Split the input into individual hashes
    #     hashes = hash_input.split()

    #     for hash in hashes:
    #         hash_pattern = r"^[a-fA-F\d]+$"
    #         if not re.match(hash_pattern, hash):
    #             QMessageBox.warning(self.view, "Invalid Input", f"Invalid hash: {hash}")
    #             return

    #         try:
    #             attack_thread = self.model.crack_hash(hash, hash_type, "Dictionary Attack", self.dictionary_file_path)
    #             attack_thread.password_cracked.connect(self._update_output)  # connect the signal
    #             attack_thread.start()
    #             self.threads.append(attack_thread)
    #         except Exception as e:
    #             QMessageBox.warning(self.view, "Error", f"An error occurred during processing: {str(e)}")

    def start_cracking(self):
        hash_type = self.view.hash_type.currentText()

        # Check if the hash input is a file path
        hash_input = self.view.hash_input.text().strip()
        if os.path.isfile(hash_input):
            with open(hash_input, 'r') as file:
                hashes = file.read().strip().splitlines()
        else:
            hashes = [hash_input]

        for hash in hashes:
            hash_pattern = r"^[a-fA-F\d]+$"
            if not re.match(hash_pattern, hash):
                QMessageBox.warning(self.view, "Invalid Input", f"Invalid hash: {hash}")
                continue

            try:
                attack_thread = self.model.crack_hash(hash, hash_type, "Dictionary Attack", self.dictionary_file_path)
                attack_thread.password_cracked.connect(self._update_output)  # connect the signal
                attack_thread.start()
                self.threads.append(attack_thread)
            except Exception as e:
                QMessageBox.warning(self.view, "Error", f"An error occurred during processing: {str(e)}")

    # def _update_output(self, hash, password):
    #     if password is None:
    #         self.view.output_area.appendPlainText(f"Failed to crack the password: {hash}")
    #     else:
    #         self.view.output_area.appendPlainText(f"hash: {hash} Password: {password}")

    def _update_output(self, hash, password):
        if password is None:
            self.view.output_area.appendPlainText(f"Failed to crack the hash: {hash}")
        else:
            self.view.output_area.appendPlainText(f"Hash: {hash} Password: {password}")
            try:
                self.model.save_to_db(hash, password)  # Save the hash and password to the database
            except Exception as e:
                QMessageBox.warning(self.view, "DB Saving Error", f"An error occurred while saving to the database: {str(e)}")
    def save_to_db(self):
        hash_input = self.view.hash_input.text().strip()
        output = self.view.output_area.toPlainText().strip()
        if not output:
            QMessageBox.warning(self.view, "No Output", "No cracked password to save.")
            return
        password = output.split(':')[-1].strip()
        try:
            self.model.save_to_db(hash_input, password)
            QMessageBox.information(self.view, "Saved to DB", "Cracked password has been saved to the database.")
        except Exception as e:
            QMessageBox.warning(self.view, "DB Saving Error", f"An error occurred while saving to the database")

    def export_to_file(self):
            output = self.view.output_area.toPlainText().strip()
            if not output:
                QMessageBox.warning(self.view, "No Output", "No cracked password to export.")
                return

            try:
                # Open the file in append mode
                with open(self.output_file_path, 'a') as file:  # use self.output_file_path
                    # Loop through each line in the output
                    for line in output.split('\n'):
                        # Split the line into hash and password at the first occurrence of ':'
                        parts = line.split(':', 1)
                        if len(parts) < 2:
                            continue
                        hash, password = parts[0].strip(), parts[1].strip()
                        # Write the line to the file in the format "{\n  hash: hash\n  password: password\n}"
                        file.write('{\n')
                        file.write(f'  {hash}:')
                        file.write(f' {password}\n')
                        file.write('}\n')

                QMessageBox.information(self.view, "Exported to File", "Cracked passwords have been exported to a file.")
            except Exception as e:
                QMessageBox.warning(self.view, "File Export Error", f"An error occurred while exporting to a file: {str(e)}")