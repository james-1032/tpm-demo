/**
 * Handles TPM-backed file encryption
 */
#include <string>

class DataEncrypt
{
public:
    // Default constructor for static class
    DataEncrypt() = default;

    /**
     * @brief EncryptFile Encrypts a given file using a TPM sealed key
     * @param[in] path_in File to be encrypted
     * @param[in] path_out Path where the encrypted file shall be saved
     * @param[in] key_reference Used to save the symmetric key against the TPM
     * @returns Success
     */
    static bool EncryptFile(const std::string &path_in, const std::string &path_out, const std::string &key_reference);

    /**
     * @brief EncryptData Encrypts data using a TPM sealed key
     * @param[in] data_in Data to be encrypted
     * @param[out] data_out Encrypted data output
     * @param[in] key_reference Used to save the symmetric key against the TPM
     * @returns Success
     */
    static bool EncryptData(const std::string &data_in, std::string &data_out, const std::string &key_reference);

private:

    /**
     * @brief EncryptPlaintext Encrypt some plaintext using a symmetric key
     * @param[in] symmetric_key_reference Used to unseal the symmetric key from the TPM
     * @param[in] plaintext The text to encrypt
     * @param[out] ciphertext The encrypted ciphertext
     */
    static bool EncryptPlaintext(const std::string &symmetric_key_reference, const std::string &plaintext, std::string &ciphertext_string);
};