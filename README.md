# Secure Authentication Project
> Benzon Carlitos Salazar

## Overview
In this project, you are tasked with simulating a simple user registration  and authentication program. 
Security is critical in this application. Users will have a username and a password. 
These must be stored securely so that an attacker would be unable to hijack accounts even if they gain access to the database (represented as a text file).

The purpose of this project is to learn how the cryptosystems we've studied are actually implemented in the real world.
*This is a research-heavy project, you most likely won't be able to sit down and start programming right away!*

Upon running your program, the user should be able to:
- [ ] **Enter the key(s)** which will be used for en/decryption (See the Key Distribution section for more info. Whether the user enters one or two keys will depend on the cryptosystem you choose)
- [ ] **Create a new account** (username must be unique, both must be at least 6 characters long)
- [ ] **Log in to an existing account** (username and password must be correct) and display a simple welcome message signifying a successful log-in
- [ ] **End the program**

Since security is critical for this application, classical ciphers will not suffice.  In order to securely store our sensitive information, we must use a **modern cipher**.  Suggestions include (but are not limited to):
- DES
- AES
- Triple-DES
- RSA