import os
import time
from functions_cli import login, signup, input_data, read_data

CSV_FILE_PATH = 'user_data.csv'

def main():
    print("Welcome to the Secure Data Management System")
    
    while True:
        # Show main menu
        print("\nSelect an option:")
        print("1. Login")
        print("2. Signup")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == "1":
            # Login process
            if login(CSV_FILE_PATH):
                print("You are now logged in.")
                while True:
                    # After successful login, show additional options
                    print("\nSelect an action:")
                    print("1. Encrypt and store data")
                    print("2. Read and decrypt data")
                    print("3. Logout")
                    user_choice = input("Enter your choice (1/2/3): ").strip()

                    if user_choice == "1":
                        # Encrypt and store data
                        input_data(username=input("Enter your username: ").strip(), csv_file_path=CSV_FILE_PATH)
                    elif user_choice == "2":
                        # Read and decrypt data
                        read_data(username=input("Enter your username: ").strip(), csv_file_path=CSV_FILE_PATH)
                    elif user_choice == "3":
                        print("Logging out...")
                        break
                    else:
                        print("Invalid choice! Please try again.")
        elif choice == "2":
            # Signup process
            signup(CSV_FILE_PATH)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
