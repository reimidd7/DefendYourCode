import hashlib
import os
import binascii
name_pattern = r"^[a-zA-Z]{1,50}$"
int_pattern = r"^-?\d+$"
input_file_pattern = r"^[a-zA-Z0-9_-]{1,211}.[a-zA-Z]{1,10}$"
output_file_pattern = r"^[a-zA-Z0-9_-]{1,211}.txt$"
name_pattern = r"^[a-zA-Z]{1,50}$"
int_pattern = r"^-?\d+$"

first_name = ""
last_name = ""
value_int1 = 0
value_int2 = 0
input_file = ""
output_file = ""



def getName(prompt):
    name = input(prompt)
    while not re.match(name_pattern, name):
        name = input("Invalid name. Please enter a valid name: ")
    return name


def getValidInt(prompt):
    while True:
        value = input(prompt)
        if re.match(int_pattern, value):
            value = int(value)
            if -2 ** 31 <= value <= 2 ** 31 - 1:
                return value
            else:
                print("The number entered is out of range for a Java int.")
        else:
            print("Invalid input. Please enter a valid integer.")

def hash_password(password):
    """Hash a password using PBKDF2 with HMAC-SHA256 and salt."""
    salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(pwdhash).decode('ascii'), binascii.hexlify(salt).decode('ascii')

def verify_password(stored_password, stored_salt, provided_password):
    """Verify if the provided password matches the stored password."""
    salt = binascii.unhexlify(stored_salt)
    pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return stored_password == binascii.hexlify(pwdhash).decode('ascii')

def get_password():
    while True:
        password = input("Enter a password: ")
        password_hash, salt = hash_password(password)
        verify_password_attempt = input("Re-enter your password for verification: ")

        if verify_password(password_hash, salt, verify_password_attempt):
            print("Password set successfully.")
            with open('passwordPython.txt', 'w') as f:
                f.write(f"{password_hash}\n") # Write password to file
            break
        else:
            print("Passwords do not match. Please try again.")

get_password()

def getValidInputFile(prompt):
    while True:
        input_file = input(prompt)
        if re.match(input_file_pattern, input_file):
            try:
                open(input_file)
                return input_file
            except FileNotFoundError as e:
                print("File not found: " + input_file)
                continue
        else:
            print("Invalid input. Enter a local file name (format: \"filename.extension\").")
            continue

def getValidOutputFile(prompt):
    output_file = input(prompt)
    while not re.match(output_file_pattern, output_file):
        output_file = input("Enter an output file name for a text file (.txt): ")
    return output_file

def printToOutputFile():
    sum = value_int1 + value_int2
    mult = value_int1 * value_int2
    try:
        with open(output_file, "w") as writer:
            writer.write("First Name: " + first_name + "\n")
            writer.write("Last Name: " + last_name + "\n")

            writer.write("Sum: " + str(sum) + "\n")
            writer.write("Product: " + str(mult) + "\n")

            with open(input_file, "r") as reader:
                writer.write("Input File Name: " + input_file + "\n")
                writer.write("Input File Contents:\n")
                for line in reader:
                    writer.write(line)
        print("Data written to " + output_file + " successfully")
    except IOError as e:
        print("Writing to file failed")


if __name__ == "__main__":
    # Main.main(sys.argv)
    first_name = getName("Enter your first name (1 to 50 letters): ")
    last_name = getName("Enter your last name (1 to 50 letters): ")
    value_int1 = getValidInt("Enter a valid integer: ")
    value_int2 = getValidInt("Enter another valid integer: ")

    input_file = getValidInputFile("Enter an input file name for a local file (no paths allowed, must be in local directory, max 211 characters): ")
    output_file = input("Enter an output file name for a text file (no paths allowed, must end in .txt, max 211 characters): ")

    # get the values and write them to the output file
    printToOutputFile()

