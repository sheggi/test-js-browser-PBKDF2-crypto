# Test PBKDF2 Crypto in Browser
Simple proof of concept of how to use PBKDF2 to derive key for symmetirc de/encryption.

## process
encrypting
- get user password
- derive key wit PBKDF2
- use key to symetrically encrpyt plain text

decrypting
- get user password
- derive key wit PBKDF2
- use key to decrypt cyphertext

## possible usecases

Encrypt data without sending password to the server.

Encrypt private key with password.

## disclaimer
This code is not safe for production. Use different configurations for `config.salt` and `config.iv`. Make sure, these configurations enable a strong security.