import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.io.*;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Main {
    private static Scanner SCANNER = new Scanner(System.in);
    private static final Pattern NAME_PATTERN = Pattern.compile("^[A-Za-z]{1,50}$");
    private static final String ERROR_LOG_FILE = "errorLog.txt";
    private static String firstName;
    private static String lastName;
    private static int value1;
    private static int value2;
    private static String password;

    public static void main(String[] args) {
        while (true) {
            getInput();
            getPassword();
            break;
        }

        //printToOutputFile();
    }

    private static void getInput() {
        String prompt = "Enter your first name (1 to 50 characters): ";
        firstName = getName(prompt);
        lastName = getName(prompt);
        value1 = getIntegerValue();
        value2 = getIntegerValue();

        System.out.println("You entered: " + firstName + " " + lastName + " " + value1 + " " + value2);
    }

    private static String getName(String prompt) {
        String firstName;
        do {
            System.out.println(prompt);
            firstName = SCANNER.nextLine();
            System.out.println("You entered: " + firstName);
        } while (!NAME_PATTERN.matcher(firstName).matches());

        return firstName;
    }

    private static int getIntegerValue() {
        String input;
        int value = 0;
        boolean isValid;
        Pattern integerPattern = Pattern.compile("-?\\d{1,10}");
        do {
            System.out.println("Enter an integer value: ");
            input = SCANNER.nextLine();
            isValid = integerPattern.matcher(input).matches();
            if (isValid) {
                try {
                    value = Integer.parseInt(input);
                } catch (NumberFormatException e) {
                    logError(e);
                    System.out.println("Invalid input. Please enter a valid integer.");
                    isValid = false;
                }
            } else {
                System.out.println("Invalid input. Please enter a valid integer.");
            }
        } while (!isValid);

        return value;
    }

    private static byte[] getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private static String getPassword()
    {
        byte[] salt = getSalt();
        String hashedPassword = "";
        String verifyPasswordHash = "";

        do {
            System.out.println("Enter a password: ");
            password = SCANNER.nextLine();
            hashedPassword = generatePasswordHash(password, salt);
            System.out.println("Re-enter your password for verification: ");
            String verifyPassword = SCANNER.nextLine();
            verifyPasswordHash = generatePasswordHash(verifyPassword, salt);

            if (!hashedPassword.equals(verifyPasswordHash)) {
                System.out.println("Passwords do not match. Please try again.");
            }
        } while (!hashedPassword.equals(verifyPasswordHash));
    
        try (FileOutputStream out = new FileOutputStream("passwordJava.txt")) {
            // Write password to file
            out.write(( hashedPassword).getBytes());
        } catch (IOException e)
        {
            logError(e);
        }

        return password;
    }

    private static String generatePasswordHash(String password, byte[] salt)
    {
        try
        {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return toHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error while hashing a password: " + e.getMessage(), e);
        }
    }

    private static String toHex(byte[] array) throws NoSuchAlgorithmException {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    private static void logError(Exception e) {
        try (PrintWriter log = new PrintWriter(new FileOutputStream(new File(ERROR_LOG_FILE), true))) {
            log.println(e.getMessage());
        } catch (FileNotFoundException ex) {
            System.out.println("An error occurred while trying to log an error.");
        }
    }

    private static boolean isValid(String input, Pattern regEx) {
        Matcher matcher = regEx.matcher(input);
        return matcher.matches();
    }

    /*
     * Asks user for an input file name, and checks it.
     * Follows Microsoft Standards for file names.
     * Does NOT allow a path to be added!
     */
    private static String getInputFileName() {
        String inputFile;
        boolean inDir = true;
        // set up reg ex
        String regExIFile = "^[a-zA-Z0-9_\\-]{1,211}\\.[a-zA-Z]{1,10}$";
        Pattern regEx = Pattern.compile(regExIFile);

        do {
            System.out
                    .print("Enter an input file name for a local file (no paths allowed, must be in local directory, " +
                            "max 211 characters): ");
            inputFile = SCANNER.nextLine();

            if (isValid(inputFile, regEx)) {
                try {
                    new FileInputStream(inputFile);
                    break; // Break the loop if the file is found
                } catch (FileNotFoundException e) {
                    inDir = false;
                    logError(e);
                    System.out.println("File not found: " + inputFile);
                }
            } else {
                System.out.println("Invalid input. Enter an local file name (format: \"filename.extension\"). ");
            }

        } while (!isValid(inputFile, regEx) || !inDir);

        return inputFile;
    }

    /*
     * Asks user for an output file name, and checks it.
     * Follows Microsoft Standards for file names.
     * Does NOT allow a path to be added!
     */
    private static String getOutputFileName() {
        String outputFile;
        // set up reg ex
        String regExOFile = "^[a-zA-Z0-9_\\-]{1,211}\\.txt$";
        Pattern regEx = Pattern.compile(regExOFile);

        // ask for user input

        System.out.print(
                "Enter an output file name for a text file (no paths allowed, must end in .txt, max 211 characters): ");
        outputFile = SCANNER.nextLine();
        while (!isValid(outputFile, regEx)) {
            System.out.print("Enter an output file name for a text file (.txt): ");
            outputFile = SCANNER.nextLine();
        }

        return outputFile;
    }

    private static void printToOutputFile() {

        BigInteger firstInt = BigInteger.valueOf(value1); // BigInteger solves integer overflow problems
        BigInteger secondInt = BigInteger.valueOf(value2);
        BigInteger sum;
        BigInteger mult;
        String inputFileName = getInputFileName();
        String outputFileName = getOutputFileName();

        try {
            PrintWriter writer = new PrintWriter(outputFileName);

            // Write user's name
            writer.println("First name: " + firstName);
            writer.println("Last name: " + lastName);

            // Write sum of integers
            sum = firstInt.add(secondInt);
            writer.println("Sum: " + sum);

            // Write product of integers
            mult = firstInt.multiply(secondInt);
            writer.println("Product: " + mult);

            // Write contents of the input file
            BufferedReader reader = new BufferedReader(new FileReader(inputFileName));
            String line;
            writer.println("Input File Name: " + inputFileName);
            writer.println("Input File Contents:");
            while ((line = reader.readLine()) != null) {
                writer.println(line);
            }
            reader.close();

            writer.close();
            System.out.println("Data written to " + outputFileName + " successfully.");
        } catch (IOException e) {
            logError(e);
            e.printStackTrace();
        }
    }
}