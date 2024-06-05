# Secure Coding Principles Project

This project demonstrates the secure coding principles learned in class. It includes two implementations of the same program, one in Java and one in Python, that showcase defensive programming techniques to ensure proper input validation, error handling, and secure password storage.

## Team Members
- Brodi Matherly
- Reilly Middlebrooks
- Amanda Nguyen

## Project Overview
The program performs the following tasks:
1. Prompts the user for their first name and last name (maximum 50 characters each).
   - Input validation is performed using regular expressions to ensure only alphabetic characters are allowed.
2. Prompts the user for two integer values within the range of a 4-byte integer.
   - Input validation is performed to ensure the entered values are valid integers within the specified range.
   - In the Java implementation, `BigInteger` is used to prevent integer overflow during calculations.
3. Prompts the user for the name of an input file.
   - Input validation is performed to ensure the file name follows the specified format and exists in the local directory.
4. Prompts the user for the name of an output file.
   - Input validation is performed to ensure the file name follows the specified format and ends with the ".txt" extension.
5. Prompts the user to enter a password, stores the hashed password using a salt, and verifies the password when re-entered.
   - The password is hashed using the PBKDF2 algorithm with HMAC-SHA256 and a randomly generated salt.
   - The hashed password is stored in a file (`passwordJava.txt` for Java, `passwordPython.txt` for Python) for future reference.
6. Opens the output file and writes the user's name, the sum and product of the two integers (without overflow), and the contents of the input file.
   - File handling is performed securely using appropriate file streams and proper closing of resources.

The program ensures that proper input is obtained from the user and handles any errors gracefully, logging them to an error log file (in the Java implementation). It keeps running until valid input is provided.

## Implementation Details
The project includes two implementations of the program:
1. Java implementation (located in the `java` folder)
   - Utilizes `BigInteger` for integer calculations to prevent overflow.
   - Implements error logging to a separate file (`errorLog.txt`).
2. Python implementation (located in the `python` folder)
   - Handles integer overflow automatically without the need for special data types.
   - Performs input validation and error handling similar to the Java implementation.

Both implementations follow defensive programming practices to ensure secure coding principles are applied.

## Testing
Thorough testing has been performed on both implementations to ensure the program handles various scenarios, including edge cases, improper input, and general cases. The testing output captures can be found in the respective implementation folders:
- Java testing output: `java/testing_output.txt`
- Python testing output: `python/testing_output.txt`

Please refer to the testing output files for detailed information on the test cases covered.

## Known Limitations
- The Java implementation logs errors to a separate file (`errorLog.txt`), while the Python implementation does not include explicit error logging.
- The hashed passwords are stored in plain text files (`passwordJava.txt` and `passwordPython.txt`). It is important to ensure these files are stored securely and not accessible to unauthorized users.

## Defensive Measures
The following defensive measures have been implemented in the code:
- Input validation using regular expressions to ensure data integrity and prevent malicious input.
- Secure password hashing using PBKDF2 with HMAC-SHA256 and a random salt to protect user passwords.
- Error handling and logging (in the Java implementation) to gracefully handle exceptional scenarios and maintain program stability.
- Proper file handling techniques to prevent resource leaks and ensure data is written and read securely.

## Notes
- The program has been designed to handle various input scenarios and prevent crashes or errors.
- The code has been kept clean and readable for easy understanding and maintenance.
- The program has been tested thoroughly to ensure its robustness and security.
