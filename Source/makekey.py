from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#-----------------------------------------------------------------------------
 # SOURCE FILE:    makekey.py
 #
 # PROGRAM:        makekey.py
 #
 # DATE:           November 2, 2021
 #
 # REVISIONS:      N/A
 #
 # DESIGNER:       Kevin Lo
 #
 # PROGRAMMER:     Kevin Lo
 #
 # NOTES:
 # A simple program that creates a new key, both the attacker and victim need
 # to be using the same key as this is a symmetrical key
 # the key needs to be renamed to key1.key to use in both the victim and attacker machines
# --------------------------------------------------------------------------
keyOutName = "newkey.key"
#Create a key and save it somewhere
key = Fernet.generate_key()
with open(keyOutName, 'wb') as filekey:
    filekey.write(key)
f = Fernet(key)
