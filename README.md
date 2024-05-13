# tpm-demo

A demo project highlighting the use of a hardware TPM to encrypyt/decrypt files (or data from memory).

Not a complete or polished implementation, but can be used as an example of this technique.

# Build

```sh
mkdir _build
cd build
cmake ../
make
```

This generates a _demo_exe_ application and a shared library that can be used by another project.

# Demo app example

```
TPM-Encrypt Demo:
1. Encrypt a file
2. Decrypt a file
3. Delete associated TPM data
4. Delete **all** TPM data
5. Exit
```
```
Enter your choice: 1
Enter the path of the file to encrypt: plaintext_secret.txt
Enter the path of the encrypted output file: encrypted_secret.bin
Enter the key reference (Used to decrypt the file later): my_reference
```
```
Enter your choice: 2
Enter the path of the file to decrypt: encrypted_secret.bin
Enter the path of the plaintext output file: decrypted_secret.txt
Enter the key reference (Used to decrypt the file): my_reference
```
