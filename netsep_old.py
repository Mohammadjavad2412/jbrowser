import sys
from PyQt5.QtWidgets import QApplication, QMainWindow,QFileDialog
from PyQt5.QtGui import QIcon
from PyQt5.QtWebEngineWidgets import QWebEngineView,QWebEngineDownloadItem
from PyQt5.QtCore import QUrl,QSettings

class BrowserApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.settings = QSettings("Netpardaz", "NetSep")
        self.browser = QWebEngineView()
        # Set window title
        self.setWindowTitle("NET SEP")
        # Set window icon
        self.browser.page().profile().downloadRequested.connect(self.downloadRequested)
        self.setWindowIcon(QIcon("Bank_maskan.ico"))
        self.browser.setUrl(QUrl("http://172.16.0.170:4173"))
        self.setCentralWidget(self.browser)
        self.showMaximized()
        
    def downloadRequested(self, download: QWebEngineDownloadItem):
        # Get the suggested file name from the download
        suggested_filename = download.suggestedFileName()

        # Use QFileDialog to choose a download location
        options = QFileDialog.Options()
        download_path, _ = QFileDialog.getSaveFileName(self, "Save File", suggested_filename, "All Files (*)", options=options)

        if download_path:
            # Set the download location and start the download
            download.setPath(download_path)
            download.accept()
        else:
            # Cancel the download if the user chooses not to save the file
            download.cancel()
        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = BrowserApp()
    sys.exit(app.exec_())
