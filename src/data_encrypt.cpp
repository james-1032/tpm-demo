#include "tpm_encrypt/data_encrypt.hpp"
#include "tpm_encrypt/common.hpp"

#include <iostream>
#include <cstring>

#include <openssl/evp.h>


// Command Notes
/**
 * tpm2_changeauth can be useful during the initial setup process:
 *
 * Set owner authorization to newpass
 *  tpm2_changeauth -c owner newpass
 *
 * or
 *
 *  tpm2_changeauth -c o -p newpass newerpass
 *
 * or *Reset to empty pass*
 *
 *  tpm2_changeauth -c o -p oldpass
 *
 */

/**
 * tpm2_rc_decode can be used to decode a TPM error code
 */

/**
 * Handles TPM-backed encryption
 */

/**
 * @brief EncryptFile Encrypts a given file using a TPM sealed key
 * @param[in] path_in File to be encrypted
 * @param[in] path_out Path where the encrypted file shall be saved
 * @param[in] key_reference Used to save the symmetric key against the TPM
 */
bool DataEncrypt::EncryptFile(const std::string &path_in, const std::string &path_out, const std::string &key_reference)
{
    // Load our file into memory
    std::string file_contents{};
    if (!Common::FileToString(path_in, file_contents))
    {
        std::cerr << "Unable to load file: " << path_in << std::endl;
        return false;
    }

    // Hold our encrypted data
    std::string encrypted_contents{};

    // Encrypt the file contents
    if (!EncryptData(file_contents, encrypted_contents, key_reference))
    {
        std::cerr << "Unable to encrypt the requested file: " << path_in << std::endl;
        return false;
    }

    if (!Common::StringToFile(path_out, encrypted_contents))
    {
        std::cerr << "Unable to write encrypted data at: " << path_out << std::endl;
        return false;
    }

    return true;
}

/**
 * @brief EncryptData Encrypts data using a TPM sealed key
 * @param[in] data_in Data to be encrypted
 * @param[out] data_out Encrypted data output
 * @param[in] key_reference Used to save the symmetric key against the TPM
 */
bool DataEncrypt::EncryptData(const std::string &data_in, std::string &data_out, const std::string &key_reference)
{
    try
    {
        // We need to generate and seal our symmetric encryption key against the TPM
        if (!Common::GenerateSealedKey(key_reference))
        {
            std::cerr << "Unable to generate sealed encryption key for data" << std::endl;
            return false;
        }

        // Encrypt our key using the TPM sealed key we just generated and write to file
        if (!EncryptPlaintext(key_reference, data_in, data_out))
        {
            std::cerr << "Unable to encrypt plaintext" << std::endl;
            return false;
        }
    }
    catch (std::runtime_error &e)
    {
        std::cerr << e.what() << std::endl;
        return false;
    }

    return true;
}

/**
 * @brief EncryptPlaintext Encrypt some plaintext using a symmetric key
 * @param[in] symmetric_key_reference Used to unseal the symmetric key from the TPM
 * @param[in] plaintext The text to encrypt
 * @param[out] ciphertext The encrypted ciphertext
 */
bool DataEncrypt::EncryptPlaintext(const std::string &symmetric_key_reference, const std::string &plaintext, std::string &ciphertext_string)
{

    // Unseal the key and associated iv
    std::vector<uint8_t> unsealed_encrypted_key{};
    std::vector<uint8_t> unsealed_encrypted_iv{};
    if (!Common::UnsealKey(symmetric_key_reference, unsealed_encrypted_key, unsealed_encrypted_iv))
    {
        std::cerr << "Unable to unseal key, have you provided a valid reference?" << std::endl;
        return -1;
    }

    std::cout << "Encrypting file..." << std::endl;

    /* Message to be encrypted */
    unsigned char *plaintext_char = reinterpret_cast<unsigned char *>(const_cast<char *>(plaintext.c_str()));

    EVP_CIPHER_CTX *ctx;

    int len = 0;
    int ciphertext_len = 0;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        std::cerr << "EVP_CIPHER_CTX_new failed" << std::endl;
        return false;
    }

    /*
     * Initialise the encryption context
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, unsealed_encrypted_key.data(), unsealed_encrypted_iv.data()))
    {
        std::cerr << "EVP_EncryptInit_ex failed" << std::endl;
        return false;
    }

    // Store result
    unsigned char ciphertext[plaintext.length() * 2];
    //std::vector<unsigned char> ciphertext(plaintext.length() * 2);


    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext_char, strlen((char *)plaintext_char)))
    {
        std::cerr << "EVP_EncryptUpdate failed" << std::endl;
        return false;
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        std::cerr << "EVP_EncryptFinal_ex failed" << std::endl;
        return false;
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    // Return ciphertext
    ciphertext_string = std::string(reinterpret_cast<char *>(ciphertext), ciphertext_len);
    return true;
}