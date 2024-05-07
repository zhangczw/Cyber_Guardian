# Cyber Guardian

**Cyber Guardian** is a Python application designed to enhance digital self-defense by providing secure user authentication and cryptographic functionalities. This project was developed by Weiqi Zhang for the MFIN2275 Digital Self-Defense with Python course with Professor Paul Romer.

## Project Overview

The primary objective of Cyber Guardian is to create a secure system for registering and authenticating users while offering advanced cryptographic functions for data protection. It utilizes bcrypt for hashing passwords, keyring for key management, and NaCl for digital signing.

### Target Audience

**Cyber Guardian** is ideal for: - Students interested in learning about cybersecurity concepts through practical applications. - Developers working on user authentication and cryptographic security. - Anyone looking to better understand secure coding practices.

## Features

-   **User Registration**: Users can register with a secure username and password.
-   **User Login**: Log in using registered credentials, with varying access levels.
-   **Password Hashing**: Securely hashes passwords using bcrypt.
-   **Role-Based Access**:
    -   **Administrator**: View all registered users and manage the system.
    -   **Normal User**: Access specific functions like encryption and digital signing.
-   **Graphical User Interface (GUI)**: Developed with Tkinter for ease of use.

## Getting Started

### Prerequisites

-   **Python 3.8+**: Ensure you have the required Python version.
-   **Cyber_Guardian.py**: Ensure you have the required Python file.

### Installation

1.  **Clone this Repository**:

    ``` bash
    git clone https://github.com/zhangczw/Cyber_Guardian
    cd Cyber_Guardian
    ```

2.  **Install Dependencies**:

    Install the required packages via `requirements.txt`:

    ``` bash
    pip install -r requirements.txt python -m 
    python -m pip install PySide6 PyNaCl keyring
    ```

3.  **Configure `.spec` File**:

    Before building the executable, update the `script_dir` variable in the `Cyber_Guardian.spec` file to match the directory where you have downloaded the project files. This is necessary for PyInstaller to locate your Python script and associated data file correctly.

    ``` python
    # Open the Cyber_Guardian.spec file and find the following line:
    script_dir = '/Users/weiqizhang/DSD_content/Cyber_Guard_File'
    # Replace it with the path to the directory where you cloned the repository, for example:
    script_dir = '/path/to/your/downloaded/Cyber_Guard_File'
    ```

4.  **Build and Run**:

    Build the executable using PyInstaller: `pyinstaller Cyber_Guardian.spec`

5.  **Launch the Application**:

    Navigate to the `dist` directory and execute the application: `cd dist/Cyber_Guardian  ./Cyber_Guardian`

## Main Components and Dependencies

-   **Python Libraries**:
    -   `keyring`: Secure management of cryptographic keys.
    -   `bcrypt`: Password hashing library.
    -   `nacl`: Provides cryptographic signing and verification.
    -   `tkinter`: GUI development.
-   **Application Modules**:
    -   `register.py`: Handles user registration.
    -   `login.py`: Manages user login functionality.
    -   `admin.py`: Administrator functions.
    -   `encrypt_decrypt.py`: Encryption and decryption features.
    -   `digital_signing.py`: Digital signing operations.

## Security Considerations

-   **Password Security**: Passwords are securely hashed using bcrypt, but storing hashed passwords locally could pose risks if the file is compromised.
-   **Keyring Security**: Protect your keyring with a strong system password.
-   **Access Control**: Ensure only authorized administrators can access sensitive information.

## Future Improvements

-   **Encryption**: Encrypt the JSON data files to improve security.
-   **Multi-Factor Authentication**: Implement additional authentication layers.
-   **Activity Logging**: Record and monitor user activities for auditing.

## Lessons Learned

-   Handling dependencies and hidden imports in PyInstaller can be challenging. Make sure to explicitly list all libraries.
-   Balancing usability and security requires thoughtful design choices.

**- Weiqi Zhang**
