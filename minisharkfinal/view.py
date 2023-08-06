import PyQt5.QtWidgets as qtw
import PyQt5.QtGui as qtg
import PyQt5.QtCore as qtc

import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMenu, QVBoxLayout, QSizePolicy, QMessageBox, QWidget, QPushButton, QGridLayout, QLabel, QLineEdit, QTextEdit, QTableWidget
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidgetItem
from PyQt5.QtWidgets import QAction
from PyQt5.QtCore import pyqtSlot, QObject, pyqtSignal, QThread
from bisect import bisect_left
from collections import defaultdict


from controller import CaptureThread


# The Wireshark class is a QMainWindow subclass.
class Wireshark(QMainWindow):
    packet_emitted = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.packet_list = []
        self.capture_thread = CaptureThread()
        self.capture_thread.packet_emitted.connect(self.packetHandler)
        self.table_widget = QTableWidget()
        # self.capture_thread.packet_emitted.connect(self.filterPacket)
        # self.capture_thread.start()

        self.initUI()
        self.table_widget.clicked.connect(self.show_packet_details)
        self.packet_dict = defaultdict(list)

    def initUI(self):
        self.setWindowTitle("Minishark")
        self.setGeometry(100, 100, 800, 600)

        # Create a status bar
        self.statusBar().showMessage('Ready')

        # Create a toolbar
        toolbar = self.addToolBar('Toolbar')
        captureAction = QAction(
            QIcon('icons/start.png'), 'Start Capture', self)
        stopAction = QAction(QIcon('icons/stop.png'), 'Stop Catpure', self)
        restartAction = QAction(
            QIcon('icons/reload.png'), 'Restart Capture', self)
        saveAction = QAction(QIcon('icons/save.png'), 'Save Packets', self)
        aboutAction = QAction(QIcon('icons/about.png'), 'About', self)

        # Connect actions to their respective slots/methods
        captureAction.triggered.connect(self.startCapture)
        stopAction.triggered.connect(self.stopCapture)
        restartAction.triggered.connect(self.restartCapture)
        saveAction.triggered.connect(self.savePackets)
        aboutAction.triggered.connect(self.about)

        # Add actions to the toolbar
        toolbar.addAction(captureAction)
        toolbar.addAction(stopAction)
        toolbar.addAction(restartAction)
        toolbar.addAction(saveAction)
        toolbar.addAction(aboutAction)

        # Create a central widget
        centralWidget = QWidget(self)
        self.setCentralWidget(centralWidget)

        # Create a grid layout
        gridLayout = QGridLayout()
        centralWidget.setLayout(gridLayout)

        # Create a label
        label = QLabel('Minishark', self)
        label.setAlignment(Qt.AlignCenter)
        label.setFont(qtg.QFont('Arial', 24))
        gridLayout.addWidget(label, 0, 0, 1, 4)

        # Create a line edit
        self.lineEdit = QLineEdit(self)  # assign to self.lineEdit
        self.lineEdit.setPlaceholderText('Enter a filter')
        gridLayout.addWidget(self.lineEdit, 1, 0, 1, 4)

        # Create a text edit
        self.textEdit = QTextEdit(self)
        gridLayout.addWidget(self.textEdit, 2, 0, 1, 4)

        # Create a button
        filterbutton = QPushButton('Apply', self)
        gridLayout.addWidget(filterbutton, 3, 0, 1, 4)
        filterbutton.clicked.connect(self.filterPacket)

        # Create a label
        label = QLabel('Packet List', self)
        label.setAlignment(Qt.AlignCenter)
        label.setFont(qtg.QFont('Arial', 16))
        gridLayout.addWidget(label, 4, 0, 1, 4)

        # Create a table widget
        self.table_widget = QTableWidget(self)
        self.table_widget.setColumnCount(4)
        self.table_widget.setHorizontalHeaderLabels(
            ['Time', 'Source', 'Destination', 'Protocol'])
        gridLayout.addWidget(self.table_widget)
        self.table_widget.clicked.connect(self.show_packet_details)

        # Create a label
        label = QLabel('Packet Details', self)
        label.setAlignment(Qt.AlignCenter)
        label.setFont(qtg.QFont('Arial', 16))
        gridLayout.addWidget(label, 6, 0, 1, 4)

        # Create a text edit
        self.packetDetail = QTextEdit(self)
        gridLayout.addWidget(self.packetDetail, 7, 0, 1, 4)

        # Show the window
        self.show()

    def startCapture(self):
        """
        The function "startCapture" starts a capture thread and displays a message in the status bar
        indicating that capturing is in progress.
        """
        self.capture_thread.start()
        # print("starting")
        self.statusBar().showMessage('Capturing')

    def stopCapture(self):
        """
        The function `stopCapture` stops a capture thread and displays a message in the status bar.
        """
        self.capture_thread.stop()
        self.statusBar().showMessage('Stopped')

    def savePackets(self):
        """
        The function saves captured packets to a file, either overwriting the existing file or appending
        to it based on user confirmation.
        :return: nothing (None).
        """
        if not self.packet_list:
            msgBox = QMessageBox()
            msgBox.setIcon(QMessageBox.Information)
            msgBox.setText(
                "No packets have been captured. Please start the packet capture first.")
            msgBox.setWindowTitle("No Packets Captured")
            msgBox.exec()
            return

        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText(
            "Do you want to overwrite the existing packets.txt file?")
        msgBox.setWindowTitle("Overwrite Confirmation")
        msgBox.setStandardButtons(QMessageBox.Yes | QMessageBox.No)

        returnValue = msgBox.exec()
        if returnValue == QMessageBox.Yes:
            # If 'Yes' is clicked, overwrite the existing file
            with open('packets.txt', 'w') as f:
                for packet in self.packet_list:
                    f.write(str(packet) + '\n')
        elif returnValue == QMessageBox.No:
            # If 'No' is clicked, append to the existing file
            with open('packets.txt', 'a') as f:
                for packet in self.packet_list:
                    f.write(str(packet) + '\n')

    def about(self):
        msgBox = QMessageBox()
        msgBox.setWindowTitle("About Minishark")
        msgBox.setText("Minishark v1.0\nCreated by  Avishek Dhakal")
        msgBox.exec()

    def restartCapture(self):
        """
        The function restartCapture clears the packet list, resets the table widget, shows a capturing
        message in the status bar, and starts the capture thread.
        """
        self.packet_list.clear()
        self.table_widget.setRowCount(0)
        self.statusBar().showMessage('Capturing')

        # Restart the capture thread
        self.capture_thread.start()

    def show_packet_details(self, qmodelindex):
        """
        The function `show_packet_details` displays the details of a captured packet in a text field.
        
        :param qmodelindex: The `qmodelindex` parameter is an object that represents the index of an
        item in a model. It is typically used in Qt frameworks to identify the position of an item in a
        list or table view. In this case, it is used to identify the row of the selected packet in the
        model
        """
        row = qmodelindex.row()
        packet = self.capture_thread.capture_instance.captured_packets[row]
        packet_details = packet.show(dump=True)
        self.packetDetail.setText(packet_details)

    @pyqtSlot(list)
    def packetHandler(self, packet):
        """
        The function `packetHandler` appends a packet to a list, adds a new row to a table widget, and
        populates the row with the packet data.
        
        :param packet: The `packet` parameter is a list that represents a packet of data. It is assumed
        to have multiple elements, and the last element is used as a key in the `packet_dict`
        dictionary. The other elements are used to populate the columns of a table in the `table_widget`
        """
        self.packet_list.append(packet)
        row_count = self.table_widget.rowCount()  # Get the current row count
        self.table_widget.setRowCount(row_count + 1)  # Add one new row

        for c, column in enumerate(packet):
            item = QTableWidgetItem(column.strip())
            self.table_widget.setItem(row_count, c, item)

        self.packet_dict[packet[-1]].append(packet)

    # @pyqtSlot()

    def filterPacket(self):
        """
        The function filters packets based on a given filter value and displays the filtered packets.
        """
        filter_value = self.lineEdit.text()
        filter_type, filter_text = filter_value.split(" ")
        if filter_type.lower() in ['protocol', 'src', 'dst']:
            if filter_type.lower() == 'protocol':
                filtered_packets = self.packet_dict.get(
                    filter_text.upper(), [])
            else:
                ip_index = 1 if filter_type.lower() == 'src' else 2
                for packets in self.packet_dict.values():
                    for packet in packets:
                        if ":" in packet[ip_index]:
                            ip, _ = packet[ip_index].split(":")
                            if ip == filter_text:
                                filtered_packets.append(packet)
                        elif packet[ip_index] == filter_text:
                            filtered_packets.append(packet)

        self.textEdit.clear()

        # Display the filtered packets
        for packet in filtered_packets:
            self.textEdit.append(str(packet))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Wireshark()
    sys.exit(app.exec_())




