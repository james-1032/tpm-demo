/**
 * Common methods for TPM interactions
 */
#include <string>
#include <tss2/tss2_fapi.h>
#include <memory>
#include <vector>

class Common
{
public:
    /**
     * @brief UnsealKey Reads an encryption key from the TPM
     * @param[in] key_reference A name/refernece for this key, used to access it
     * @param[out] unsealed_key_data The unsealed encryption key/data
     * @param[out] unsealed_key_data The unsealed encryption iv/data
     */
    static bool UnsealKey(const std::string &key_reference, std::vector<uint8_t> &unsealed_key_data, std::vector<uint8_t> &unsealed_iv_data);

    /**
     * @brief GenerateSealedKey Creates and seals a symmetric key at the reference provided
     * @param[in] key_reference Reference where the key can be stored and later retrieved
     * @returns Success
     */
    static bool GenerateSealedKey(const std::string &key_reference);

    /**
     * @brief FapiContextDeleteWrapper Wrapper used to finalise a FAPI context on destruction
     * @param[in] pointer Pointer to the FAPI context
     */
    static void FapiContextDeleteWrapper(FAPI_CONTEXT *pointer);

    /**
     * @brief FileToString Loads a file into a std::string
     * @param[in] path_in File to read
     * @param[out] data_out File contents output
     * @returns Success
     */
    static bool FileToString(const std::string &path_in, std::string &data_out);

    /**
     * @brief StringToFile Saves a std::string into a file
     * @param[in] path_out File to write
     * @param[in] data_in File contents input
     * @returns Success
     */
    static bool StringToFile(const std::string &path_out, std::string &data_in);

    /**
     * @brief AuthCallback Presents authentication to the TPM when requested
     */
    static TSS2_RC AuthCallback(
        char const *objectPath,
        char const *description,
        const char **auth,
        void *userData);

    /**
     * @brief ResetTpm Completely remove user generated data on this TPM
     */
    static void ResetTpm();

    /**
     * @brief GetRandomData Fetches random data from the system's entropy source
     * @param[out] data_buffer The buffer to populate
     * @param[in] length The amount of random data to fetch
     */
    static void GetRandomData(unsigned char data_buffer[], const size_t &length);
};