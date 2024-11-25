import csv
import random
import base64
import re
import string
import numpy as np  
import os

def login(csv_file_path):
    try:
        user_data = {}
        with open(csv_file_path, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                user_data[row["username"]] = row["password"]
        username = input("Enter username: ")
        if username not in user_data:
            print("Username not found!")
            return False
        attempts = 3
        while attempts > 0:
            password = input("Enter password: ")
            if password == user_data[username]:
                print("Login successful!")
                return True
            else:
                attempts -= 1
                print(f"Incorrect password. You have {attempts} attempts left.")
        print("Too many failed attempts. Login failed.")
        return False
    except FileNotFoundError:
        print("CSV file not found!")
        return False
    except Exception as err:
        print(f"Error: {err}")
        return False

def signup(csv_file_path):
    """
    Signup function to add a new user to the CSV database.
    Ensures password meets strength requirements using pass_check.
    
    :param csv_file_path: Path to the CSV file containing user data.
    """
    try:
        # Check if the CSV file exists
        file_exists = os.path.exists(csv_file_path)

        # Prompt for username
        username = input("Enter a username: ").strip()

        # Check if username already exists
        if file_exists:
            with open(csv_file_path, mode='r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if row["username"] == username:
                        print("Username already exists! Please try another one.")
                        return

        # Prompt for a strong password
        while True:
            password = input("Enter a password: ").strip()
            if pass_check(password):
                break  # Password is strong enough

        # Generate access key
        access_key = generate_access_key()

        # Write new user data to the CSV file
        with open(csv_file_path, mode='a', newline='') as file:
            writer = csv.writer(file)
            
            # Write header if the file is newly created
            if not file_exists:
                writer.writerow(["username", "password", "access_key", "encrypted_data"])

            # Write the new user's data
            writer.writerow([username, password, access_key, ""])

        print(f"Signup successful! Your access key is: {access_key}. Store it somewhere safe. You'll need it to access your data.")

    except Exception as err:
        print(f"Error during signup: {err}")

def pass_check(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    if re.search(r"\s", password):
        return False
    return True

def generate_access_key(length=16):
    if length < 8:
        raise ValueError("Access key length must be at least 8 characters.")
    
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(random.choices(chars, k=length))

def input_data(username, csv_file_path):
    """
    Allows the user to encrypt and store data in the CSV file after a successful login.
    
    :param username: The username of the logged-in user.
    :param csv_file_path: Path to the CSV file containing user data.
    """
    try:
        # Prompt user for action
        choice = input("Do you want to encrypt and store your data? (yes/no): ").strip().lower()
        if choice != "yes":
            print("No data will be encrypted or stored.")
            return

        # Ask for file path to encrypt
        file_path = input("Enter the file path to encrypt: ").strip()
        if not os.path.exists(file_path):
            print("File not found!")
            return

        # Encrypt the data
        encrypted_data = final_encrypt(file_path)
        if not encrypted_data:
            print("Encryption failed!")
            return

        # Read the CSV file and update the user's record
        updated_rows = []
        user_found = False

        with open(csv_file_path, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["username"] == username:
                    row["encrypted_data"] = encrypted_data
                    user_found = True
                updated_rows.append(row)

        # If user not found (shouldn't happen after login), return error
        if not user_found:
            print("Error: User not found in the database.")
            return

        # Write the updated data back to the CSV file
        with open(csv_file_path, mode='w', newline='') as file:
            fieldnames = ["username", "password", "access_key", "encrypted_data"]
            writer = csv.DictWriter(file, fieldnames=fieldnames)

            # Write header and rows
            writer.writeheader()
            writer.writerows(updated_rows)

        print("Encrypted data has been successfully stored.")
    except Exception as err:
        print(f"Error during input data operation: {err}")

def final_encrypt(path, encryption_key=1):
    """
    Performs Base64 encoding and Fourier encryption, prepares the result for CSV storage.
    
    :param path: Path to the file to be encrypted.
    :param encryption_key: Key for Fourier encryption.
    :return: Encrypted data as a list of rows suitable for CSV storage.
    """
    encrypted_data = fourier_encrypt(path, encryption_key)
    if not encrypted_data:
        return None
    try:
        # Create a list of rows with real and imaginary parts
        csv_data = [["Real Part", "Imaginary Part"]]  # Header row
        csv_data.extend([[value.real, value.imag] for value in encrypted_data])
        return csv_data
    except Exception as err:
        print(f"Error preparing data for CSV: {err}")
        return None

def base64_encrypt(path):
    """
    Encodes a file's binary data into a Base64 string.
    
    :param path: Path to the file to be encoded.
    :return: Base64 encoded string.
    """
    try:
        with open(path, "rb") as file:
            binary_data = file.read()
            base64_encoded = base64.b64encode(binary_data)
            base64_string = base64_encoded.decode("utf-8")
            return base64_string
    except FileNotFoundError:
        print("File not found!")
        return None
    except Exception as err:
        print(f"Error: {err}")
        return None

def fourier_encrypt(path, encryption_key=1):
    """
    Encrypts a file's data using Fourier Transform and an encryption key.
    
    :param path: Path to the file to be encrypted.
    :param encryption_key: Key for Fourier encryption.
    :return: Encrypted data as a NumPy array of complex numbers.
    """
    base64_string = base64_encrypt(path)
    if not base64_string:
        return None
    try:
        # Convert Base64 string to numerical representation
        numeric_data = np.array([ord(char) for char in base64_string], dtype=np.float64)

        # Apply Fourier Transform
        frequency_components = np.fft.fft(numeric_data)

        # Manipulate the frequency components with the encryption key
        encrypted_frequencies = frequency_components * encryption_key

        return encrypted_frequencies
    except Exception as err:
        print(f"Error during Fourier encryption: {err}")
        return None
    
def read_data(username, csv_file_path):
    """
    Allows the user to read and decrypt their stored data after successful login.
    
    :param username: The username of the logged-in user.
    :param csv_file_path: Path to the CSV file containing user data.
    """
    try:
        # Ask for the access key
        access_key = input("Enter your access key: ").strip()

        # Read the CSV file and check the access key
        user_found = False
        encrypted_data = None
        with open(csv_file_path, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["username"] == username and row["access_key"] == access_key:
                    encrypted_data = row["encrypted_data"]
                    user_found = True
                    break

        # If user not found or incorrect access key
        if not user_found:
            print("Incorrect access key or username not found.")
            return

        # Decrypt the data (Inverse Fourier Transform)
        decrypted_data = decrypt_data(encrypted_data)
        if decrypted_data is None:
            print("Decryption failed!")
            return

        # Ask for the filename to save the decrypted data
        save_path = input("Enter the path where you want to save the decrypted file: ").strip()

        # Save the decrypted data to the file
        with open(save_path, "wb") as file:
            file.write(decrypted_data)

        print(f"Decrypted data saved successfully to {save_path}.")

    except Exception as err:
        print(f"Error during read data operation: {err}")

def decrypt_data(encrypted_data):
    """
    Decrypts the encrypted data stored in CSV (real and imaginary parts of Fourier transform).
    
    :param encrypted_data: The encrypted data as a CSV-friendly string.
    :return: The decrypted binary data.
    """
    try:
        # Convert the encrypted data back into a list of complex numbers (real + imaginary parts)
        encrypted_data_list = [list(map(float, row)) for row in encrypted_data]
        encrypted_complex = [complex(row[0], row[1]) for row in encrypted_data_list[1:]]  # Skip the header

        # Perform Inverse Fourier Transform to get the original numerical data
        numeric_data = np.fft.ifft(encrypted_complex)

        # Convert the numerical data back to a Base64 string
        decrypted_base64 = ''.join(chr(int(round(val.real))) for val in numeric_data)
        
        # Decode the Base64 string to get the original binary data
        decrypted_binary = base64.b64decode(decrypted_base64)
        
        return decrypted_binary
    except Exception as err:
        print(f"Error during decryption: {err}")
        return None
