/**
 * Handles TPM-backed file decryption
 */
#include <string>
#include <tss2/tss2_fapi.h>
#include <memory>
#include <vector>

class DataDecrypt
{
public:
    // Default constructor for static class
    DataDecrypt() = default;

    /**
     * @brief DecryptFile Decrypts a given file using a TPM sealed key
     * @param[in] path_in File to be decrypted
     * @param[in] path_out Path where the decrypted file shall be saved
     * @param[in] key_reference The symmetric key reference used to seal this data
     * @returns Success
     */
    static bool DecryptFile(const std::string &path_in, const std::string &path_out, const std::string &key_reference);

    /**
     * @brief DecryptData Decrypts data using a TPM sealed key
     * @param[in] data_in Data to be decrypted
     * @param[out] data_out Decrypted data output
     * @param[in] key_reference Used to save the symmetric key against the TPM
     * @returns Success
     */
    static bool DecryptData(const std::string &data_in, std::string &data_out, const std::string &key_reference);

    /**
     * Decrypt some ciphertext using a symmetric key
     * @param symmetric_key_reference Used to unseal the symmetric key from the TPM
     * @param plaintext The text to decrypt
     * @return std::string The decrypted plaintext
     */
    static int DecryptCiphertext(const std::string &ciphertext, const std::string &symmetric_key_reference, unsigned char *plaintext);

    };