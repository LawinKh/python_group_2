import json 
import re
import random
import string

# Caesar cipher encryption and decryption functions (pre-implemented)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function (optional)
def is_strong_password(password):
    if len(password) < 8: # Checking if the password is at least 8 characters long
        return False
    if not re.search("[a-z]", password): # Checking for at least one small letter
        return False
    if not re.search("[A-Z]", password): # Checkking for at least one upper case letter
        return False
    if not re.search("[0-9]", password): # Checking for at least one number 
        return False
    if not re.search("[@#$%^&+=]", password): # Checking for at least one special character
        return False
    return True  # If return is True, all conditions are met, the password is recognized as strong and accepted

''' RegEx Functions
re.search is a function found in Python's re module which can be used when working with regular expressions (REGEX).
re.search looks through a string and stops at the first match it finds (W3school, RegEx). Accessed 25 May 2025
https://www.w3schools.com/python/python_regex.asp
'''

# Password generator function (optional) 
def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation #See explanation below
    password = ''.join(random.choice(characters) for i in range(length)) #"See explanation below
    return password

'''
"string.ascii_letters" contains the combination of all lowercase and uppercase letters (a-z, A-Z). On the other hand,
"string.digits" includes collection of all the numbers (0-9). Also, "string.punctuation" contains the collection of all
special characters (!@#$%^&*, etc.). Overall, this creates a big pool of all characters that can be used in the
password. Source: Python.org, string — Common string operations, String constants. Accessed: https://docs.python.org/3/library/string.html
'''

'''
The string method ".join(...)" joins all the randomly chosen characters into a single string which is the password in
this case. We have empty string before .join so that there is no empty space between characters. In addition, "random.choice(characters)" selects one random character from the pool. The "for i in
range(length)" is a loop that repeats the process of character selection based on the password length inserted by the user. 
'''

# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []

# Function to add a new password 
def add_password():
    website = input("Enter the website: ") # This input asks user for the website.
    username = input("Enter the username: ") # This input asks for the username related to the website inserted
    password = input("Enter the password: ") # This input asks for the password related to the previous two inputs. 

    # Optionally check password strength 
    if is_strong_password(password):
        print("Password is strong.")
    else:
        print("Password is not strong enough. Create a stronger password using uppercase, lowercase, numbers and a special symbols.")

    ''' The "optionally check password strength" section of the code checks the strength of the password in connection with
    the code inserted in the "Password strength checker function (optional)" above.
    '''

    # Optionally generate a random strong password
    generate_option = input("Would you like to generate a strong password? (yes/no): ")
    if generate_option.lower() == "yes": #If the user inserts an uppercase word or letters, then the answer is converted to lowercase. 
        length = int(input("Enter the desired length of the password: ")) # This asks for the desired password length, for example, if user inserts 12, then the password length generated includes 12 characters.
        password = generate_password(length) # Generate a random strong password. This is connected to the "Password generator function (optional)" code section found above.  
        print(f"Generated password: {password}")

    encrypted_password = caesar_encrypt(password, 3) # This line of code encrypts the password with a Caesar cipher (shift of 3). This shifting changes to the third next character.  
    websites.append(website) # Add the website to the list before saving to "vault.txt"
    usernames.append(username) # Add the username to the list before saving to "vault.txt"
    encrypted_passwords.append(encrypted_password) # Add the encrypted password to the list before saving to "vault.txt"
    print("Password added successfully!")

'''
The following source explains Caesar Cipher Encryption through examples:
https://www.geeksforgeeks.org/caesar-cipher-in-cryptography/
'''

# Function to retrieve a password 
def get_password():
    website = input("Enter the website: ")
    if website in websites:
        index = websites.index(website) #index refers to the position in the list.
        username = usernames[index] #index refers to the position in the list.
        encrypted_password = encrypted_passwords[index] #index refers to the position in the list.
        decrypted_password = caesar_decrypt(encrypted_password, 3)  # Once again, the shift value is 3 for the encryption and decryption returns it to the original character.
        print(f"Username: {username}")
        print(f"Password: {decrypted_password}")
    else:
        print("Website not found.")

# Function to save passwords to a JSON file 
def save_passwords():
    data = {
        "websites": websites,
        "usernames": usernames,
        "encrypted_passwords": encrypted_passwords
    }
    with open("vault.txt", "w") as file:
        json.dump(data, file)
    print("Passwords saved successfully!") 

    ''' 
    "json.dump(data, file)" converts the dictionary data into JSON format and writes it into "vault.txt".
    '''

# Function to load passwords from a JSON file 
def load_passwords():
    global websites, usernames, encrypted_passwords # Global refers to connecting information in silos 
    with open("vault.txt", "r") as file:
        data = json.load(file)
        websites = data["websites"]
        usernames = data["usernames"]
        encrypted_passwords = data["encrypted_passwords"]

''' Loading function works so it is like when you play a playstation game and you save the data, and to start the game
again where you finished, you load the saved data to start the game at the checkpoint you were at.
'''

''' The global keyword in Python is used to access and modify variables that are defined outside the current
function. It allows a function to connect to variables that are elsewhere in the program.
'''

# Main method
def main():
    while True:
        print("\nPassword Manager Menu:")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Save Passwords")
        print("4. Load Passwords")
        print("5. Quit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            add_password()
        elif choice == "2":
            get_password()
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            passwords = load_passwords()
            print("Passwords loaded successfully!")
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")

# Execute the main function when the program is run
if __name__ == "__main__":
    main()


'''
Zeljka, Lawin and Stefan
Group 2
Fundamentals of Programming
Group assignment: Password Manager
Laurea UAS
4 May 2025
'''