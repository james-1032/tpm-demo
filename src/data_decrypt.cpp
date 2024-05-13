#include "tpm_encrypt/data_decrypt.hpp"
#include "tpm_encrypt/common.hpp"

#include <iostream>
#include <openssl/evp.h>
#include <fstream>
#include <filesystem>

/**
 * @brief DecryptFile Decrypts a given file using a TPM sealed key
 * @param[in] path_in File to be decrypted
 * @param[in] path_out Path where the decrypted file shall be saved
 * @param[in] key_reference The symmetric key reference used to seal this data
 * @returns Success
 */
bool DataDecrypt::DecryptFile(const std::string &path_in, const std::string &path_out, const std::string &key_reference)
{

    std::ifstream file(path_in, std::ios::binary); // Open the file

    if (!file.is_open())
    {
        std::cerr << "Failed to open the file." << std::endl;
        return false;
    }

    // Use ostringstream to concatenate strings
    std::ostringstream oss;
    oss << file.rdbuf();                        // Read the entire file into the stringstream
    std::string encrypted_contents = oss.str(); // Convert stringstream to string

    file.close(); // Close the file


    // Hold our plaintext
    std::string decrypted_contents{};

    // Decrypt the file contents
    if (!DecryptData(oss.str(), decrypted_contents, key_reference))
    {
        std::cerr << "Unable to decrypt the requested file: " << path_in << std::endl;
        return false;
    }

    if (!Common::StringToFile(path_out, decrypted_contents))
    {
        std::cerr << "Unable to write plaintext data at: " << path_out << std::endl;
        return false;
    }

    return true;
}

/**
 * @brief DecryptData Decrypts data using a TPM sealed key
 * @param[in] data_in Data to be decrypted
 * @param[out] data_out Decrypted data output
 * @param[in] key_reference Used to save the symmetric key against the TPM
 * @returns Success
 */
bool DataDecrypt::DecryptData(const std::string &data_in, std::string &data_out, const std::string &key_reference)
{

    unsigned char plaintext[data_in.size()];
    //std::vector<unsigned char> plaintext(data_in.size());

    int plaintext_length = DecryptCiphertext(data_in, key_reference, plaintext);
    if (plaintext_length == -1)
    {
        // Failed to decrypt
        return false;
    }

    std::string plaintext_string(reinterpret_cast<char *>(plaintext), plaintext_length);

    data_out = plaintext_string;

    return true;
}

/**
 * Decrypt some ciphertext using a symmetric key
 * @param symmetric_key_reference Used to unseal the symmetric key from the TPM
 * @param plaintext The text to decrypt
 * @return std::string The decrypted plaintext
 */
int DataDecrypt::DecryptCiphertext(const std::string &ciphertext, const std::string &symmetric_key_reference, unsigned char *plaintext)
{

    // Unseal the key and associated iv
    std::vector<uint8_t> unsealed_encrypted_key{};
    std::vector<uint8_t> unsealed_encrypted_iv{};
    if (!Common::UnsealKey(symmetric_key_reference, unsealed_encrypted_key, unsealed_encrypted_iv))
    {
        std::cerr << "Unable to unseal key, have you provided a valid reference?" << std::endl;
        return -1;
    }

    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        std::cerr << "EVP_CIPHER_CTX_new failed" << std::endl;
        return -1;
    }

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, unsealed_encrypted_key.data(), unsealed_encrypted_iv.data()))
    {
        std::cerr << "EVP_DecryptInit_ex failed" << std::endl;
        return -1;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    std::cout << "Decoding " << ciphertext.length() << " bytes..." << std::endl;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, reinterpret_cast<unsigned char *>(const_cast<char *>(ciphertext.c_str())), ciphertext.length()))
    {
        std::cerr << "EVP_DecryptUpdate failed" << std::endl;
        return -1;
    }
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    int res = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (1 != res)
    {
        std::cerr << "EVP_DecryptFinal_ex failed: " << res << std::endl;
        return -1;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Done" << std::endl;

    return plaintext_len;
}