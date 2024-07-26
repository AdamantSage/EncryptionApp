# EncryptionApp
Introduction
Our task is to implement an Encryption/Decryption algorithm that encrypts and decrypts the following file formats, images, text files, RAR or zip files, and PowerPoint using a password on an intuitive user interface. We have decided to make use of Python programming language to accomplish this task. Amongst plentiful of choices to accomplish the task, our team decided to make use of a password, SHA256 Hashing, cipher and AES encryption algorithm to both encrypt and decrypt files.
Processes
Encryption process
Our teams algorithm first requires a user to set their desired method of encryption. Set a password to input to encrypt and decrypt a file. The user opens a file directory to select a file path. By clicking Browse after locating the file to encrypt in the file directory, our algorithm obtains the file path as a location to save the decrypted file and later remove the original file. Now, the user can initiate the process of encryption by clicking the encrypt button. Before the process begins, the user is prompt to enter the initial password set. The algorithm then converts the password into bytes, as the hash library requires bytes as an input. The hash, is then used to construct the poly-alphabetic substitution for the cipher. The contents of the file are, first, ciphered using the poly-alphabetic substitution, then, encrypted using the Advanced Encryption Standard (AES). The algorithm saves the encrypted file, removes the original file, and also extends the file with the “.aes” file type - which is specific to our algorithm process. Lastly, the algorithm gives a report whether the encryption was a success or not with a pop up, and a status of encryption - if whether the process is done or not.
Process for encryption (.txt, .rar, .zip, .pptx and image files)



											
								       






