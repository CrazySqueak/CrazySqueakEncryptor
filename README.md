
**DISCLAIMER: THIS PROGRAM DOES NOT GUARANTEE UNCRACKABLE SECURITY. IF YOU NEED YOUR FILES TO BE KEPT TRULY SECURE, INVEST IN A PROFESSIONAL SOLUTION. CrazySqueak, and any other authors, do not in any way, shape, or form, guarantee that your files will be kept secure.**  
**DISCLAIMER #2: None of the authors (including CrazySqueak), do not accept any liability or responsibility for any data loss, or other problems, caused by improper operation of the program, or by failure of the program. You use it at your own risk.**  

## Python folder encryption program  
This is an encryption program, written in Python 3.6, that encrypts files and stores them in a "vault". The only way to get the files out is to use the same keyword that the files were encrypted with.  
    
## How secure is it.  
This program is **not** secure. It was designed as a side-project, not a marketable security program. As such, it only protects against average computer users, not hackers or experienced code-breakers.  
The encryption the program uses is a polyalphabetic solution, based on the [Vigenère Square][1], but modified to use base64 plus an extra character (The '#'). This makes it secure against those who haven't done their research, but fairly easy to crack if a file encrypted with it has an easy-to-guess file structure when in the clear (i.e. Text documents, which consist entirely of plaintext).  
  
## Features  
Despite the insecurity of the program, there are still some additional security features added to it, to help protect against those who don't know what they're doing, as well as some simple integrity checks and miscellaneous features. These include:  
 * There are no references, or hashes, to or of the key or unencrypted files, stored anywhere in the vault. A cracker will only find that their key is incorrect once they try to decrypt the vault with it.  
 * Filenames and directory names are also encrypted, protecting against the fact that files generated using the pickle module contain any strings in the clear, readable using most text editors.  
 * "Blocks", once encrypted, have an sha512 hash generated, to help check their integrity.  
  
## Creating a new 'Vault'  
 1. To launch the program, launch the "encryptor.py" program using python 3. A window should pop up, with three entry fields and two buttons.  
 2. Enter the path you'd like to store the vault at.  
 3. If you are creating a new vault, enter the path of the folder you want to encrypt into the second box.  
 4. Enter your encryption key into the third box. Make sure you don't forget it, because then it's a lot harder to get your files back.  
 5. Click "New Vault".  
 6. Wait patiently while it encrypts your files for the first time. The window should change to "Please wait...", followed by "Estimating block amount...", before displaying "Encrypting files..." alongside some information on progress, and a wait time estimate.  
 7. Get yourself something to do if you have a lot of files, or some very large ones. The Earth is probably due to be destroyed to make a hyperspace byway at some time before the encryption will finish. As I said, this isn't designed to be practical.  
 8. Once the encryption is complete, a new window will appear. Use "Open Folder" to open the folder containing your decrypted files, "Change Key" to change the encryption key, or "Close Vault", to close the vault.  
 9. **Do not close the window if you want to properly close the vault. Closing the window will not re-encrypt the files back into the vault, and wipe the decrypted files.** Instead, enter your key into the required box and use the "Close Vault" option.  
 10. Contemplate whether the encryption will be finished before the heat death of the universe.  
 11. Once the encryption is complete, the decrypted files will be overwritten and deleted, safely removing them with no hope of recovery (unless the drive they were on was an SSD, due to wear-levelling algorithms) without the vault and encryption key.  
  
## Opening a 'Vault'  
 1. As previously discussed, open the program.  
 2. Type the path that the vault was stored at into the first box.  
 3. Leave the second box as-is unless you want to store the decrypted files in a different location.  
 4. Enter the encryption key into the third box.  
 5. Click "Open".  
 6. Wait while the decryption process runs a quick integrity check on the vault.  
 7. Find out some cheeky devil deleted block #402 and panic. Alternatively, provided that didn't happen, proceed to step 8 without panicking.  
 8. Provided the integrity checks passed, the files will be decrypted, at a similarly slow rate to encrypting them.  
 9. Trust me, it takes about 3-5 minutes to process 201MB of files on my computer, which has a core i5.  
 10. Once it's decrypted, see steps 8-11 of "Creating a new vault."  
  
## FAQ  
 * My vault is corrupt, what do I do?  
  There is unfortunately no way to recover vaults at the moment.  
 * I've forgotten my encryption key!  
  Unfortunately, there is no way to recover your encryption key. Instead, you'll have to approach  the situation like someone else trying to break in, and maybe take better care of your encryption key next time.  
 * Is this program guaranteed to keep my files secure?  
  Nope. See the disclaimer at the top of the document. If you need a faster and more secure program, you should look at solutions designed to be practical, rather than simply designed to exist.  
 * The program doesn't open.  
  Please make sure that you are launching it correctly, are using the correct version of python (Tested on 3.6+), and are running the correct file. Also, please make sure that you have **all** of the required files (encryptionlib.py, and encryptor.py) in the same folder as each other.  
 * Can I re-use the "encryptionlib.py" file as a module for my own program.  
  Yes. Just please make sure that your program is legal, that you don't modify the comments at the top of the file, other than to add your name to the list if you modified the file, and make sure to warn any users that the encryption is not a very secure solution.  
 * Why does this take so loooooong?  
  This is python. You have to be patient, or use a different solution. Also, this program is not meant to be practical. Solution: Don't encrypt gigabytes of data.  
  
## Licensing  
For licensing information, see LICENSING.md  
   
[1]: https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher
