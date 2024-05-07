import os
import json
import bcrypt
import time
from tkinter import Tk, Label, Entry, Button, messagebox, Frame, Listbox, Toplevel, filedialog
import keyring
import base64
from nacl.signing import SigningKey, VerifyKey
from nacl.secret import SecretBox
from nacl.encoding import HexEncoder, Base64Encoder
from datetime import datetime

# Admin credentials
ADMIN_USERNAME = ''
ADMIN_PASSWORD_HASH = bcrypt.hashpw(''.encode(), bcrypt.gensalt())

# Get the directory where the script is located
script_directory = os.path.dirname(os.path.abspath(__file__))

# File path for storing user credentials
file_path = os.path.join(script_directory, 'Cyber_Guard_File.json')

def load_users():
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print("User data file not found. Creating a new one.")
        return {}
    except json.JSONDecodeError:
        print("Error decoding JSON. Check file format.")
        return {}

# Takes dict into JSON file
def save_users(users):
    try:
        with open(file_path, 'w') as file:
            # Convert python dict into JSON formatted string and write directly to file
            json.dump(users, file, indent=4)
        print("Users saved successfully.")
    except Exception as e:
        print("Failed to save users:", str(e))

#Password Hashing During Registration
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Compare entered hash wirh the stored hash -> return True/False
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode(), hashed_password.encode())

# GUI Implementation with Tkinter
# Basic setup and main frame
class UserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberGuardian: Secure Document Management")
        self.setup_main_frame()
        self.signing_key, self.verify_key = self.generate_keys()
        
    # Main frame and widgets
    def setup_main_frame(self):
        self.main_frame = Frame(self.root)
        self.main_frame.pack(pady=20)
        Label(self.main_frame, text="Username:").grid(row=0, column=0)
        self.username_entry = Entry(self.main_frame)
        self.username_entry.grid(row=0, column=1)
        Label(self.main_frame, text="Password:").grid(row=1, column=0)
        self.password_entry = Entry(self.main_frame, show='*')
        self.password_entry.grid(row=1, column=1)
        Button(self.main_frame, text="Login", command=self.login_user).grid(row=2, column=1, pady=10)
        Button(self.main_frame, text="Register", command=self.register_user).grid(row=2, column=0, pady=10)

    def generate_keys(self):
        try:
            # Keyring
            # Key chekcing and retrieving
            # Return None if DNE
            encryption_key = keyring.get_password("CyberGuardian", "encryption_key")
            signing_key_encoded = keyring.get_password("CyberGuardian", "signing_key")
            # Generating and storing new keys
            if not encryption_key or not signing_key_encoded:
                signing_key = SigningKey.generate()
                encryption_key = base64.b64encode(SigningKey.generate().encode()).decode('utf-8')
                signing_key_encoded = signing_key.encode(encoder=HexEncoder).decode('utf-8')
                keyring.set_password("CyberGuardian", "encryption_key", encryption_key)
                keyring.set_password("CyberGuardian", "signing_key", signing_key_encoded)
            else:
                # Retrieving and Using Keys for operations
                signing_key = SigningKey(signing_key_encoded.encode('utf-8'), encoder=HexEncoder)
            verify_key = signing_key.verify_key
            return signing_key, verify_key
        except Exception as e:
            messagebox.showerror("Key Generation Error", f"Failed to generate keys: {e}")
            return None, None

    def login_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        users = load_users()
        if username == ADMIN_USERNAME and bcrypt.checkpw(password.encode(), ADMIN_PASSWORD_HASH):
            messagebox.showinfo("Login Success", "Administrator login successful")
            self.show_admin_controls()
            # First Check if the username is in the database
            # Then check the pwd if its correct
        elif username in users and check_password(users[username]['password'], password):
            messagebox.showinfo("Login Success", "Login successful")
            self.show_user_controls(username)
        else:
            messagebox.showerror("Login Error", "Invalid username or password")

    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        users = load_users()
        if username in users:
            messagebox.showerror("Error", "Username already exists")
        else:
            users[username] = {
                #storing hashed passwords
                'password': hash_password(password),
                'created': datetime.now().strftime("%Y-%m-%d"),
                'role': 'user'
            }
            save_users(users)
            messagebox.showinfo("Registration Success", "User registered successfully")
            self.show_user_controls(username)

    def show_admin_controls(self):
        admin_window = Toplevel(self.root)
        admin_window.title("Admin Controls")
        listbox = Listbox(admin_window, height=10, width=50)
        listbox.pack(pady=10)
        Button(admin_window, text="Refresh", command=lambda: self.refresh_user_list(listbox)).pack(pady=10)
        self.refresh_user_list(listbox)

    def refresh_user_list(self, listbox):
        users = load_users()
        listbox.delete(0, 'end')
        for user, details in users.items():
            listbox.insert('end', f"{user} - Created: {details['created']}, Role: {details['role']}")

    def show_user_controls(self, username):
        user_window = Toplevel(self.root)
        user_window.title("Secure Document Options")
        Button(user_window, text="Encrypt Document", command=lambda: self.process_document(user_window, username, "encrypt")).pack(pady=10)
        Button(user_window, text="Decrypt Document", command=lambda: self.process_document(user_window, username, "decrypt")).pack(pady=10)
        Button(user_window, text="Sign Document", command=lambda: self.process_document(user_window, username, "sign")).pack(pady=10)
        Button(user_window, text="Verify Document", command=lambda: self.process_document(user_window, username, "verify")).pack(pady=10)

    def process_document(self, parent, username, action):
        file_path = filedialog.askopenfilename()
        if file_path:
            if action == "encrypt":
                self.encrypt_document(file_path)
            elif action == "decrypt":
                self.decrypt_document(file_path)
            elif action == "sign":
                self.sign_document(file_path, username)
            elif action == "verify":
                self.verify_document(file_path, username)

    def encrypt_document(self, file_path):
        try:
            # retrieve key
            secret_key = base64.b64decode(keyring.get_password("CyberGuardian", "encryption_key"))
            # SecretBox Instantiations
            box = SecretBox(secret_key)
            # Reading and Encrypting the Document
            with open(file_path, 'rb') as file:
                plaintext = file.read()
            encrypted = box.encrypt(plaintext)
            encrypted_file_path = file_path + ".enc"
            with open(encrypted_file_path, 'wb') as enc_file:
                enc_file.write(encrypted)
            messagebox.showinfo("Encryption Complete", "File encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"An error occurred during encryption: {e}")

    def decrypt_document(self, file_path):
        try:
            # retrieve key
            secret_key = base64.b64decode(keyring.get_password("CyberGuardian", "encryption_key"))
            box = SecretBox(secret_key)
            # Reading the encrypted Document
            with open(file_path, 'rb') as file:
                ciphertext = file.read()
            decrypted = box.decrypt(ciphertext)
            decrypted_file_path = file_path.replace(".enc", "")
            # Saving the decrpted Document 
            with open(decrypted_file_path, 'wb') as dec_file:
                dec_file.write(decrypted)
            messagebox.showinfo("Decryption Complete", "File decrypted successfully.")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during decryption: {e}")

    def sign_document(self, file_path, username):
        try:
            # Read document
            with open(file_path, 'rb') as file:
                message = file.read()
            # Sign the Document
            signature = self.signing_key.sign(message).signature
            signature_file_path = f"{file_path}.sig"
            # Storing the Signature
            with open(signature_file_path, 'wb') as sig_file:
                sig_file.write(signature)
            messagebox.showinfo("Signing Complete", f"Document signed successfully by {username}.")
        except Exception as e:
            messagebox.showerror("Signing Error", f"An error occurred during signing: {e}")


    def verify_document(self, file_path, username):
        try:
            # Check if the file path already ends with '.sig'
            if not file_path.endswith(".sig"):
                signature_file_path = f"{file_path}.sig"
            else:
                signature_file_path = file_path
                # Remove '.sig' to get the original document path
                file_path = file_path[:-4]  
        
            with open(file_path, 'rb') as file:
                message = file.read()
            with open(signature_file_path, 'rb') as sig_file:
                signature = sig_file.read()
            # Verify
            self.verify_key.verify(message, signature)
            # Successful Verification
            messagebox.showinfo("Verification Complete", f"Document '{file_path}' verified successfully as signed by {username}.")
        except FileNotFoundError as e:
            messagebox.showerror("Verification Error", f"File not found: {str(e)}")
        except Exception as e:
            messagebox.showerror("Verification Error", f"Verification failed for document '{file_path}': {str(e)}")



    
if __name__ == "__main__":
    root = Tk()
    app = UserApp(root)
    root.mainloop()
