# Software backend of Secure Storage of KECHB Master Key
# By George Hynes, TechyByte
# Copyright (C) George Hynes and TechyByte 2015. All rights reserved.

from otpauth import OtpAuth as auth
import hashlib
from time import sleep
from os import urandom, path
import binascii
from base64 import b64encode
import threading

# Global Variables
startkeys = 3
kdfRounds = 100000
kdfSalt = "KingEdwardVICampHillBoysTechnicalTeam"
key = ""
filenames = ["secrets.enc","secrets.dec"]
locked = False

def securityDaemon():
    while True:
        pass

def needSetup():
    files = 0
    flag = False
    global filenames
    for filename in filenames:
        if path.isfile(filename):
            files += 1
        else:
            open(filename, "w+").close()
            flag = True
    return [flag, files, len(filenames)]

def install():
    """
    Installs system including secrets data
    """
    try:
        global filenames
        for filename in filenames:
            open(filename, "w+").write("")
        secrets = []
        for i in range(10000):
            secrets.append(b64encode(urandom(16)).decode('utf-8')[:16])
        open("secrets.dec", "w+").write("\n".join(secrets))
        return True
    except:
        return False

def getKey():
    """
    Generates secret encryption/decryption key using RFID serials and HMAC/SHA256
    """
    try:
        global startkeys
        global kdfRounds
        global kdfSalt
        kdfSalt = bytes(kdfSalt, 'utf-8')
        key = ""
        for i in range(startkeys):
            key += (input("Scan Startup Key " + str(i+1) + ": "))
        key = bytes(key, "utf-8")
        key = hashlib.pbkdf2_hmac("sha256", key, kdfSalt, kdfRounds, dklen=128)
        return binascii.hexlify(key)
    except:
        return False

def startup():
    """
    Checks if setup is needed through needSetup() and either installs system or passes
    """
    try:
        global key
        setup = needSetup()
        key = getKey()
        if key is False:
            raise(Exception("Error generating key"))
        if setup[0] is False:
            pass
        else:
            if setup[1] != setup[2]:
                print("System Corrupted\nReconfiguring...")
            if install():
                pass
            else:
                raise(Exception("Error installing files"))
            print("System Successfully Setup\nPlease reboot system")
        return True
    except Exception:
        return False

def openKey():
    global locked
    locked = False
    sleep(1)

    # TODO: Unlock key here

    sleep(1)
    print("Scan a token or press # key to lock system")
    input("> ")
    sleep(1)

    # TODO: lock key here

    sleep(1)
    locked - True
    return locked


def main():
    pass

def getCounterDigit(secret="secret"):
    digPos = 1
    sha = hashlib.sha224(secret).hexdigest()
    digit = sha[digPos]
    return digit

# Check if system configured, force restart of s/w if not
if startup():
    pass
else:
    print("Error starting system, please contact software vendor.")
    exit(0)

# Start security thread
threadLcd = threading.Thread(name="daemon", target=securityDaemon)
threadLcd.setDaemon(True)

# System ready to go
main()