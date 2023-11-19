import os
import json
import sys
import logging
import traceback
from base64 import b64decode,b64encode
import hashlib
from PyQt5.QtWidgets import QApplication, QMainWindow,QLineEdit ,QFileDialog,QMessageBox
from PyQt5.QtCore import QUrl
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage,QWebEngineDownloadItem
from PyQt5.QtNetwork import QNetworkReply,QNetworkAccessManager, QNetworkRequest
from PyQt5.QtWidgets import QInputDialog
from Cryptodome.Cipher import AES
from Cryptodome import Random


class AESCipher(object):
    
    def __init__(self):
        key = "netsep"
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()
        
    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        bytes_to_remove = ord(last_character)
        return plain_text[:-bytes_to_remove]
    
    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")
    
    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

class CredentialManager:
        
    def get_credentials(self, url):
        path = os.getcwd()
        if not os.path.exists(path+"/credentials.json"):
            with open(path+"/credentials.json", "w") as file:    
                json.dump({},file)
                return None
        else:    
            with open(path+"/credentials.json", "r") as file:
                credentials = json.load(file)
                try:
                    credentials[url]
                    return credentials
                except:
                    return None

    def load_credentials(self):
        path = os.getcwd()
        if os.path.exists(path+"/credentials.json"):
            with open(path+"/credentials.json", "r") as file:
                self.credentials = json.load(file)

    def save_credentials(self, url, username, password):
        aes = AESCipher()
        encrypt_password = aes.encrypt(password)
        credentials = {}
        credentials[url] = {"username": username, "password": encrypt_password}
        with open("credentials.json", "w") as file:
            try:
                json.dump(credentials, file)
            except:
                logging.error(traceback.format_exc())
            
    def decrypt_password_by_url(self,url):
        path = os.getcwd()
        with open(path+"/credentials.json") as credentials:
            credentials = json.load(credentials)
        stored_credentials = credentials[url]
        if stored_credentials:
            encrypted_password = stored_credentials["password"]
            aes = AESCipher()
            plain_password = aes.decrypt(encrypted_password)
            return plain_password

    def verify_credentials(self, url, username, password):
        stored_credentials = self.get_credentials(url)
        if stored_credentials:
            hashed_password = stored_credentials["password"]
            # Verify the entered password against the stored hash
            return self.verify_password(password, hashed_password)
        return False

    def delete_credential(self):
        try:
            this_path = os.getcwd()
            os.remove(this_path+"/credentials.json")
        except:
            logging.error(traceback.format_exc())

class CustomWebPage(QWebEnginePage):
    
    def __init__(self, parent=None, credential_manager=None):
        super().__init__(parent)
        self.credential_manager = credential_manager
        self.authenticationRequired.connect(self.handleAuthentication)
        self.network_manager = QNetworkAccessManager()
        self.daas_url = None
        self.auth = None
        
    def acceptNavigationRequest(self, url, _type, isMainFrame):
        return True
    
    def handleAuthentication(self, url, auth):
        url = url.toString()
        cached_credentials = self.credential_manager.get_credentials(url)
        if cached_credentials:
            username = cached_credentials[url]["username"]
            password = self.credential_manager.decrypt_password_by_url(url)
        else:
        # Prompt the user for a username
            username, ok1 = QInputDialog.getText(self.view(), "NetSep", "Username:", QLineEdit.Normal)

            # Prompt the user for a password
            password, ok2 = QInputDialog.getText(self.view(), "NetSep", "Password:", QLineEdit.Password)

            # Only set the credentials if both prompts were not canceled
            if ok1 and ok2:
                self.credential_manager.save_credentials(url, username, password)
        self.daas_url = url
        self.auth = auth
        auth.setUser(username)
        auth.setPassword(password)
        req = QUrl(url)
        req.setUserName(username)
        req.setPassword(password)
        request = QNetworkRequest(req)
        reply = self.network_manager.get(request)
        reply.finished.connect(self.handle_url_loading_status)
        
    def handle_url_loading_status(self):
        # This slot is called when the URL loading is complete
        reply = self.sender()
        # Check the HTTP status code
        if reply.error() == QNetworkReply.NoError:
            pass
        elif reply.error()==QNetworkReply.AuthenticationRequiredError:
            path = os.getcwd()
            try:
                os.remove(path+"/credentials.json")
                self.show_error_message("invalid credentials passed!!")
                app.closeAllWindows()
            except:
                print(traceback.format_exc())
        else:
            errord_message = reply.errorString()
            self.show_error_message(errord_message)
            sys.exit(0)
            
    def show_error_message(self, message):
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Critical)
        msg_box.setText(message)
        msg_box.setWindowTitle("Error")
        msg_box.exec_()
            
            
class CustomBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.browser = QWebEngineView()
        self.browser.page().profile().downloadRequested.connect(self.downloadRequested)
        self.credential_manager = CredentialManager()
        self.credential_manager = self.credential_manager        
        page = CustomWebPage(self.browser, self.credential_manager)
        self.browser.setPage(page)
        self.browser.load(QUrl("http://192.168.200.2:4173"))
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
            
            
if __name__ == "__main__":
    app = QApplication(sys.argv)
    browser = CustomBrowser()
    sys.exit(app.exec_())
    