#include "tpm_encrypt/common.hpp"

#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

#include <openssl/evp.h>

static const std::string kAuthenticationString = "default_auth_key";
static const std::string kIsProvisionedIdentifier = "fapi_provisioned";

/**
 * @brief UnsealKey Reads an encryption key from the TPM
 * @param[in] key_reference A name/refernece for this key, used to access it
 * @param[out] unsealed_key_data The unsealed encryption key/data
 * @param[out] unsealed_key_data The unsealed encryption iv/data
 */
bool Common::UnsealKey(const std::string &key_reference, std::vector<uint8_t> &unsealed_key_data, std::vector<uint8_t> &unsealed_iv_data)
{

    std::cout << "Unsealing key..." << std::endl;

    // Where are we storing our sealed data on the TPM
    std::string sealed_data_path = "/HS/SRK/" + key_reference;

    // Estlabish a connection to the TPM and store within the context
    std::unique_ptr<FAPI_CONTEXT, void (*)(FAPI_CONTEXT *)> context(nullptr, &Common::FapiContextDeleteWrapper);
    auto context_pointer = context.get();

    // Initalise the connection object
    TSS2_RC tpm_result = Fapi_Initialize(&context_pointer, nullptr);
    if (tpm_result != TSS2_RC_SUCCESS)
    {
        std::cerr << "Fapi_Initialize failed with error code " << tpm_result << std::endl;
        std::cout << "[Suggestion] Does the user running this program have read/write permissions to the TPM device?" << std::endl;
        throw std::runtime_error("TPM init failed");
    }

    // Set callback presenting authentication to the TPM when required
    tpm_result = Fapi_SetAuthCB(context_pointer, AuthCallback, nullptr);
    if (tpm_result != TSS2_RC_SUCCESS)
    {
        std::cerr << "Fapi_SetAuthCB failed with error code " << tpm_result << std::endl;
        throw std::runtime_error("TPM init failed");
    }

    // Have we already provisioned this TPM? If not lets do so...
    if (!std::filesystem::exists(kIsProvisionedIdentifier))
    {

        // Provisions the TSS with its TPM (we should only do this once)
        tpm_result = Fapi_Provision(context_pointer, nullptr, nullptr, nullptr);
        if (tpm_result != TSS2_RC_SUCCESS)
        {
            std::cerr << "Error: Fapi_Provision failed with error code " << tpm_result << std::endl;
            std::cout << "[Suggestion] Is this TPM already (or not) provisioned? Make sure the 'fapi_provisioned' file exists if it does" << std::endl;
            std::cout << "[Suggestion] Does this TPM have an auth key? Make sure your configuration is setup correctly..." << std::endl;
            std::cout << "[Suggestion] Change or set the TPM key using 'tpm2_changeauth'" << std::endl;
            throw std::runtime_error("TPM init failed");
        }

        // If the call was successful, save a file to mark this
        std::ofstream out_file(kIsProvisionedIdentifier);
        if (out_file.is_open())
        {
            out_file << "provisioned" << std::endl;
            out_file.close();
        }
        else
        {
            std::cerr << "TPM provisioned but unable to save status. Application may fail unless a file is created at " << kIsProvisionedIdentifier << std::endl;
            std::cout << "[Suggestion] Does the user running this application have read/write permissions at " << kIsProvisionedIdentifier << "?" << std::endl;
            throw std::runtime_error("TPM init failed");
        }
    }

    // End of initalisation

    // Temp store for our key data
    size_t key_size = 0;
    uint8_t *raw_key_bytes = nullptr;

    tpm_result = Fapi_Unseal(context_pointer, sealed_data_path.c_str(), &raw_key_bytes,
                             &key_size);
    if (tpm_result != TSS2_RC_SUCCESS)
    {
        std::cerr << "Error: Fapi_Unseal (key) failed with error code " << tpm_result << std::endl;
        return false;
    }

    // Temp store for iv data
    size_t iv_size = 0;
    uint8_t *raw_iv_bytes = nullptr;

    std::string sealed_iv_path = sealed_data_path + "_iv";

    tpm_result = Fapi_Unseal(context_pointer, sealed_iv_path.c_str(), &raw_iv_bytes,
                             &iv_size);
    if (tpm_result != TSS2_RC_SUCCESS)
    {
        std::cerr << "Error: Fapi_Unseal (iv) failed with error code " << tpm_result << std::endl;
        return false;
    }

    // Move the data into our vector
    unsealed_key_data = std::vector(raw_key_bytes, raw_key_bytes + key_size);
    unsealed_iv_data = std::vector(raw_iv_bytes, raw_iv_bytes + iv_size);

    Fapi_Free(raw_key_bytes);
    Fapi_Free(raw_iv_bytes);

    return true;
}

/**
 * @brief GenerateSealedKey Creates and seals a symmetric key at the reference provided
 * @param[in] key_reference Reference where the key can be stored and later retrieved
 * @returns Success
 */
bool Common::GenerateSealedKey(const std::string &key_reference)
{

    std::cout << "Sealing key..." << std::endl;

    // Where are we storing our sealed data on the TPM
    std::string sealed_data_path = "/HS/SRK/" + key_reference;

    // Estlabish a connection to the TPM and store within the context
    std::unique_ptr<FAPI_CONTEXT, void (*)(FAPI_CONTEXT *)> context(nullptr, &Common::FapiContextDeleteWrapper);
    auto context_pointer = context.get();

    // Initalise the connection object
    TSS2_RC tpm_result = Fapi_Initialize(&context_pointer, nullptr);
    if (tpm_result != TSS2_RC_SUCCESS)
    {
        std::cerr << "Fapi_Initialize failed with error code " << tpm_result << std::endl;
        std::cout << "[Suggestion] Does the user running this program have read/write permissions to the TPM device?" << std::endl;
        throw std::runtime_error("TPM init failed");
    }

    // Set callback presenting authentication to the TPM when required
    tpm_result = Fapi_SetAuthCB(context_pointer, AuthCallback, nullptr);
    if (tpm_result != TSS2_RC_SUCCESS)
    {
        std::cerr << "Fapi_SetAuthCB failed with error code " << tpm_result << std::endl;
        throw std::runtime_error("TPM init failed");
    }

    // Have we already provisioned this TPM? If not lets do so...
    if (!std::filesystem::exists(kIsProvisionedIdentifier))
    {

        // Provisions the TSS with its TPM (we should only do this once)
        tpm_result = Fapi_Provision(context_pointer, nullptr, nullptr, nullptr);
        if (tpm_result != TSS2_RC_SUCCESS)
        {
            std::cerr << "Error: Fapi_Provision failed with error code " << tpm_result << std::endl;
            std::cout << "[Suggestion] Is this TPM already (or not) provisioned? Make sure the 'fapi_provisioned' file exists if it does" << std::endl;
            std::cout << "[Suggestion] Does this TPM have an auth key? Make sure your configuration is setup correctly..." << std::endl;
            std::cout << "[Suggestion] Change or set the TPM key using 'tpm2_changeauth'" << std::endl;
            throw std::runtime_error("TPM init failed");
        }

        // If the call was successful, save a file to mark this
        std::ofstream out_file(kIsProvisionedIdentifier);
        if (out_file.is_open())
        {
            out_file << "provisioned" << std::endl;
            out_file.close();
        }
        else
        {
            std::cerr << "TPM provisioned but unable to save status. Application may fail unless a file is created at " << kIsProvisionedIdentifier << std::endl;
            std::cout << "[Suggestion] Does the user running this application have read/write permissions at " << kIsProvisionedIdentifier << "?" << std::endl;
            throw std::runtime_error("TPM init failed");
        }
    }

    // End of initalisation

    // Generate a 128 bit symmetric key
    std::vector<unsigned char> symmetric_key(16);
    GetRandomData(symmetric_key.data(), symmetric_key.size());

    // Seal our bytes against the TPM
    tpm_result = Fapi_CreateSeal(context_pointer, sealed_data_path.c_str(), "noDa",
                                 symmetric_key.size(),
                                 "", kAuthenticationString.c_str(), symmetric_key.data());

    // Generate a 128 bit IV (random seed data)
    std::vector<unsigned char> iv(16);
    GetRandomData(iv.data(), iv.size());

    std::string sealed_iv_path = sealed_data_path + "_iv";

    // Seal our iv bytes against the TPM
    tpm_result = Fapi_CreateSeal(context_pointer, sealed_iv_path.c_str(), "noDa",
                                 iv.size(),
                                 "", kAuthenticationString.c_str(), iv.data());

    std::cout << "Symmetric encryption key generated and sealed at: " << sealed_data_path << std::endl;
    std::cout << "IV generated and sealed at: " << sealed_iv_path << std::endl;

    return true;
}

/**
 * @brief AuthCallback Presents authentication to the TPM when requested
 */
TSS2_RC Common::AuthCallback(
    char const *objectPath,
    char const *description,
    const char **auth,
    void *userData)
{
    if (!objectPath)
    {
        return TSS2_FAPI_RC_BAD_VALUE;
    }
    *auth = kAuthenticationString.c_str();
    return TSS2_RC_SUCCESS;
}

/**
 * @brief FapiContextDeleteWrapper Wrapper used to finalise a FAPI context on destruction
 * @param[in] pointer Pointer to the FAPI context
 */
void Common::FapiContextDeleteWrapper(FAPI_CONTEXT *pointer)
{
    Fapi_Finalize(&pointer);
}

/**
 * @brief ResetTpm Completely remove user generated data on this TPM
 */
void Common::ResetTpm()
{

    // Store result of a TPM operation
    TSS2_RC tpm_result;

    // Represents a connection to the TPM via the FAPI library
    FAPI_CONTEXT *context;

    // Initalise the connection object
    tpm_result = Fapi_Initialize(&context, nullptr);
    if (tpm_result != TSS2_RC_SUCCESS)
    {
        std::cerr << "Error: Fapi_Initialize failed with error code " << tpm_result << std::endl;
        Fapi_Finalize(&context);
        return;
    }

    // Set callback presenting authentication to the TPM when required
    tpm_result = Fapi_SetAuthCB(context, AuthCallback, nullptr);
    if (tpm_result != TSS2_RC_SUCCESS)
    {
        std::cerr << "Error: Fapi_SetAuthCB failed with error code " << tpm_result << std::endl;
        Fapi_Finalize(&context);
        return;
    }

    Fapi_Delete(context, "/");

    try
    {
        if (std::filesystem::exists(kIsProvisionedIdentifier))
        {
            std::filesystem::remove(kIsProvisionedIdentifier);
            std::cout << "File deleted successfully." << std::endl;
        }
        else
        {
            std::cout << "File does not exist." << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    Fapi_Finalize(&context);
}

/**
 * @brief FileToString Loads a file into a std::string
 * @param[in] path_in File to read
 * @param[out] data_out File contents output
 * @returns Success
 */
bool Common::FileToString(const std::string &path_in, std::string &data_out)
{
    // Load our file
    std::ifstream file_stream(path_in);
    if (!file_stream.is_open())
    {
        return false;
    }

    // Read contents
    std::string file_content((std::istreambuf_iterator<char>(file_stream)),
                             std::istreambuf_iterator<char>());
    data_out = file_content;

    return true;
}

/**
 * @brief StringToFile Saves a std::string into a file
 * @param[in] path_out File to write
 * @param[in] data_in File contents input
 * @returns Success
 */
bool Common::StringToFile(const std::string &path_out, std::string &data_in)
{
    // Load our file
    std::ofstream file_stream(path_out);
    if (!file_stream.is_open())
    {
        return false;
    }

    // Write file
    file_stream << data_in;
    file_stream.close();

    return true;
}

/**
 * @brief GetRandomData Fetches random data from the system's entropy source
 * @param[out] data_buffer The buffer to populate
 * @param[in] length The amount of random data to fetch
 */
void Common::GetRandomData(unsigned char data_buffer[], const size_t &length)
{
    int fd = open("/dev/random", O_RDONLY);
    if (fd == -1)
    {
        perror("Error opening /dev/random");
        exit(1);
    }

    ssize_t bytes_read = read(fd, data_buffer, length);
    if (bytes_read < 0)
    {
        perror("Error reading from /dev/random");
        exit(1);
    }

    close(fd);
}