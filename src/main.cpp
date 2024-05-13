#include <iostream>
#include "tpm_encrypt/data_encrypt.hpp"
#include "tpm_encrypt/data_decrypt.hpp"
#include "tpm_encrypt/common.hpp"

// Entrypoint into the demo application
int main()
{

    // Main menu loop
    bool menu_active = true;
    std::string user_input;

    // TSS debug
    //putenv("TSS2_LOG=all+TRACE");

    while (menu_active)
    {
        // Display menu options
        std::cout << "TPM-Encrypt Demo:\n";
        std::cout << "1. Encrypt a file\n";
        std::cout << "2. Decrypt a file\n";
        std::cout << "3. Delete associated TPM data\n";
        std::cout << "4. Delete **all** TPM data\n";
        std::cout << "5. Exit\n";
        std::cout << "Enter your choice: ";

        // Get user input
        std::cin >> user_input;

        switch (user_input[0])
        {
        case '1':
        {
            // Handle encryption
            std::string input_file, output_file, key;
            std::cout << "Enter the path of the file to encrypt: ";
            std::cin >> input_file;
            std::cout << "Enter the path of the encrypted output file: ";
            std::cin >> output_file;
            std::cout << "Enter the key reference (Used to decrypt the file later): ";
            std::cin >> key;
            // Call EncryptFile method with user-provided parameters
            DataEncrypt::EncryptFile(input_file, output_file, key);
            break;
        }
        case '2':
        {
            // Handle decryption
            std::string input_file, output_file, key;
            std::cout << "Enter the path of the file to decrypt: ";
            std::cin >> input_file;
            std::cout << "Enter the path of the plaintext output file: ";
            std::cin >> output_file;
            std::cout << "Enter the key reference (Used to decrypt the file): ";
            std::cin >> key;
            // Call DecryptFile method with user-provided parameters
            DataDecrypt::DecryptFile(input_file, output_file, key);
            break;
        }
        case '3':
            // Handle deleting associated TPM data
            break;
        case '4':
            Common::ResetTpm();
            break;
        case '5':
            // Exit
            std::cout << "Exiting...\n";
            menu_active = false;
            break;
        default:
            std::cout << "Invalid choice. Please try again.\n";
            break;
        }
    }

    return 0;
}