# -*- coding: utf-8 -*-
#
# With this script you can print an AES cipher text to a given plaintext.
# The plaintext can be a string or the content of a file.
# You will need to define a key and depending on the chosen AES mode also an initialization vector.
#
# The script will guide you through the process:-)
#
# Author:
#   Xenia Bogomolec, indigomind@gmx.de
#

import binascii, datetime, hashlib, logging, optparse, io, os
from Crypto.Cipher import AES

# Base64 encoding is not yet included.
from base64 import b64encode, b64decode

################################################################################################
########################################### FUNCTIONS ##########################################
################################################################################################

########################################### LOGGING ############################################

currentPath = os.getcwd()
logPath = os.getcwd() + "/AES_log_files"
logPath = logPath.replace("\\", "/")
logFile = ""

def logToFile(mode, message):
    now = str(datetime.datetime.now())
    fileNow = now[:-16] + "T" + now[-15:-7].replace(":", "-") + "Z"
    os.chdir(logPath)
    global logFile
    logFile = mode + "_" + message + "_" + fileNow + ".txt"
    global logger
    logger = logging.getLogger(logFile[:-4])
    filePath = logPath + "/" + logFile
    fileHandler = logging.FileHandler(filePath)
    logger.addHandler(fileHandler), logger.setLevel(logging.DEBUG)
    if os.stat(logFile).st_size == 0:
        logger.info("AES_log_file created " + now)
    os.chdir(currentPath)

def binaryFile(hexCipher):
    os.chdir(logPath)
    file = open(logFile[:-4] + 'encr_hex.dat', 'w+')
    file.write(binascii.unhexlify(hexCipher))
    file.close()
    os.chdir(currentPath)


######################################### CIPHER CLASS ########################################

class Cipher(object):

    BS = AES.block_size # AES.bock_size is 16

    # fixed values
    AES_modes = {
        "ECB": AES.MODE_ECB,
        "CBC": AES.MODE_CBC,
        "CFB": AES.MODE_CFB,
        "OFB": AES.MODE_OFB,
        "CTR": AES.MODE_CTR,
        "OPENPGP": AES.MODE_OPENPGP,
    }

    block_ciphers = ["ECB", "CBC", "CFB", "OFB", "OPENPGP"]
    stream_ciphers = ["CTR"]

    valid_args = ["message", "key", "IV", "mode"]
    required_args = valid_args[:-1]
    ecb_required_args = valid_args[:-2]
    ctr_required_args =  ["message", "key", "mode"]

    wrong_input = 0


    def parse_args(self):
        padding = 0

        usage = """

        This is the AES encryption Printer! 

        Run it like this: 

          python parseAndPrintAES.py message=message key=key mode=ECB IV=IV ...

          1. where message is the text to encrypt,
            (message=file(absolute/path/to/file) for file content)

          2. mode is optional and in [ECB, CBC, CFB, OFB, CTR, OPENPGP],
            (default is ECB)

          3. key is the key,

          4. IV, the intitialization vector, must be 16 bytes long 
        """

        parser = optparse.OptionParser(usage)
        _, strings = parser.parse_args()

        # no defined arguments
        if not strings:
            print parser.format_help()
            parser.exit()

        AES_args = self.AES_args(strings)
        self.missingArgs(AES_args)
        self.checkInput(AES_args)
        self.printCipher(AES_args)


    ###### build a dictionary of valid arguments ######
    def AES_args(self, strings):
        AES_args = {}
        for parsedString in strings:
            parts = parsedString.split("=")
            # encrypting file input
            if parts[0] == "message" and parts[1].find("file(") > -1:
                path = parts[1].split("(")[1].split(")")[0]
                AES_args[parts[0]] = self.readFile(path)["data"]
            else:
                # putting whole message together
                if len(parts) < 2 and "message" in AES_args.keys():
                    AES_args["message"] += " " + parsedString
                # invalid arguments
                if len(parts) == 2 and parts[0] not in self.valid_args:
                    print "\n%s is not a valid argument" % (parts[0])
                # add valid argument
                elif parts[0] in self.valid_args:
                    AES_args[parts[0]] = parts[1]
        return AES_args


############################################# read file ########################################
  

    def readFile(self, filePath):
        currentPath = os.getcwd()
        filePath = filePath.replace("\\", "/")
        pathParts = filePath.split("/") 
        fileName = pathParts[len(pathParts) - 1]
        os.chdir(filePath.replace(fileName, ""))
        if fileName in os.listdir("."):
            message = open(fileName, "rb").read()
        os.chdir(currentPath)
        return {"data": message, "information": fileName[:-4]}


####################################### check arguments ######################################## 

    ###### missing input ######
    def missingArgs(self, AES_args):
        if "mode" not in AES_args.keys() or ("mode" in AES_args.keys() and AES_args["mode"] == "ECB"):
            missing_args = set(self.ecb_required_args) - set(AES_args.keys()) 
            if "mode" in AES_args.keys():
                del AES_args["mode"]
        elif "mode" in AES_args.keys() and AES_args["mode"] == "CTR":
            missing_args = set(self.ctr_required_args) - set(AES_args.keys()) 
        else:
            missing_args = set(self.required_args) - set(AES_args.keys()) 
        for arg in missing_args:
            print "\nyou forgot to define", arg
            self.wrong_input = 1

    ###### check for wrong input ######
    def checkInput(self, AES_args):
        if "mode" in AES_args.keys():
            AES_args["mode"] = AES_args["mode"].upper()
            
        if "key" in AES_args.keys():
            if len(AES_args["key"]) not in [16, 24, 32]:
                print "AES key must be either 16, 24 or 32 bytes long"
                self.wrong_input = 1

        if "IV" in AES_args.keys():
            if len(AES_args["IV"]) != 16:
                print "IV must be 16 bytes long"
                self.wrong_input = 1

        if "mode" in AES_args.keys() and AES_args["mode"] not in self.AES_modes.keys():
            print "mode has to be one of the following values [ECB, CBC, CFB, OFB, CTR, OPENPGP]"
            self.wrong_input = 1

    ###### print cipher #######
    def printCipher(self, AES_args):
        if self.wrong_input == 0:
            logToFile(AES_args["mode"] if "mode" in AES_args.keys() else "ECB", AES_args["message"][:10]) 
            ###### block ciphers ######
            if ("mode" not in AES_args.keys()) or ("mode" in AES_args.keys() and AES_args["mode"] in self.block_ciphers):
                logger.info("\noriginal message:\n" + AES_args["message"])
                ##### extend message to length which is a multiple of 16 ######
                padding = (16 - (len(AES_args["message"]) % 16)) %16
                AES_args["message"] += b'\x00'*padding
                ##### mode related printing of block AES ######
                if set(AES_args.keys()) == set(self.ecb_required_args):
                    self.printBlockAES(AES_args["message"], AES_args["key"], "0000000000000000", padding)
                if set(AES_args.keys()) == set(self.required_args):
                    self.printBlockAES(AES_args["message"], AES_args["key"], AES_args["IV"], padding)
                elif set(AES_args.keys()) == set(self.valid_args):
                    self.printBlockAES(AES_args["message"], AES_args["key"], AES_args["IV"], padding, AES_args["mode"])  
            ###### stream ciphers ######
            if "mode" in AES_args.keys() and AES_args["mode"] in self.stream_ciphers:
                print "\nYou chose a stream cipher"
                self.ctr_encrypt(AES_args["message"], AES_args["key"])
            print "\nLog file %s in directory %s" % (logFile, logPath)


################################# block cipher related functions ############################### 

    def printBlockAES(self, message, key, IV, padding, mode="ECB"):
        obj = AES.new(key, self.AES_modes[mode], IV)
        ciphertext = obj.encrypt(message)
        hexCipher = binascii.hexlify(ciphertext)
        print "\n-------------------------------------------------------------------------------"
        print "This AES encryption mode includes padding for messages with length != 0 mod 16."
        print "Without padding the length of plaintext and cipher should be equal, "
        print "respectively the encrypted hexlified text is twice as long as the message."
        print "This encrypted message includes a padding of %d whitespace/s" % (padding)
        if mode == "ECB":
            self.ecbException(obj)
        print "\n\nThe original message is:\n", message
        print "\nThe encrypted message in hexadecimal presentation of length %d is:\n%s \n" % (len(hexCipher), hexCipher)
        # encrypt IV and cut Iv from ciphertext for OPENPGP
        openpgpIV = ""
        if (mode == "OPENPGP"):
            obj1 = AES.new(key, AES.MODE_CFB, b'\x00'*self.BS, segment_size=self.BS*8) # IV for CFB
            openpgpIV = obj1.encrypt(IV + IV[-2:] + b'\x00'*(self.BS-2))[:self.BS+2]
            ciphertext = ciphertext[18:]
        decryptionIV = IV if (mode != "OPENPGP") else openpgpIV
        obj2 = AES.new(key, self.AES_modes[mode], decryptionIV)
        decryptedtext = obj2.decrypt(ciphertext)
        print "The decrypted message is:\n%s" % (decryptedtext)
        self.logEncryption(message, key, IV, padding, hexCipher, decryptedtext[:-padding] == message[:-padding], mode, decryptionIV)
        

    def ecbException(self, obj):
        ECB_example = 'my home is cosy my home is cosy '
        print "\nECB mode maps equivalent blocks of 16 characters to equivalent ciphers"
        print "e.g. '%s' maps to " % (ECB_example)
        print binascii.hexlify(obj.encrypt(ECB_example))

    def logEncryption(self, message, key, IV, padding, hexCipher, decryptedtext, mode="ECB", decryptionIV=0):
        logger.info("\nkey:\n" + key + "\n\ninitialization vector:\n" + IV + "\n\nmode:\n" + mode)
        logger.info("\nThe encrypted message in hexadecimal presentation of length %d (including a padding of 2*%d ) is:\n%s" % (len(hexCipher), padding, hexCipher))
        binaryFile(hexCipher)
        if mode == "OPENPGP":
            logger.info("\ndecryption initialization vector in hexadecimal presentation:\n" + binascii.hexlify(decryptionIV))
        logger.info("\ndecrypted message == original message:\n" + str(decryptedtext))


################################ stream cipher related functions ###############################

    @staticmethod
    def md5sum(message):
        m = hashlib.md5()
        m.update(message)
        return m.hexdigest()

    counters = []

    def _reset_counter_callback_state(self, secret):
        self.cnter_cb_called = 0
        self.secret = secret

    # the counter should be different for evry block even in different messages encrypted with the same key
    # For better performance, use Crypto.Util.Counter.
    def _encrypt_counter_callback(self): 
        self.cnter_cb_called += 1
        counter = self.randomCounter()
        counterNumber = "0" + str(self.cnter_cb_called) if (self.cnter_cb_called < 10) else self.cnter_cb_called 
        # print "counter", counterNumber , binascii.hexlify(counter)
        return counter

    def randomCounter(self):
        counter = os.urandom(Cipher.BS)
        if counter not in self.counters:
            self.counters.append(counter)
            return counter
        else:
            return self.randomCounter()

    def _decrypt_counter_callback(self): 
        self.cnter_cb_called += 1
        return self.counters[self.cnter_cb_called - 1]

    def ctr_encrypt(self, message, key):
        secret = os.urandom(Cipher.BS) # randomly choose a "secret" which is not secret
        self._reset_counter_callback_state(secret)
        cipher = AES.new(key, AES.MODE_CTR, counter = self._encrypt_counter_callback)
        ciphertext = cipher.encrypt(message) # here is where the counter is called
        hexCipher = binascii.hexlify(ciphertext)
        print "\n-------------------------------------------------------------------------------"
        print "CTR mode AES encryption with unique random counter for each block."
        print "The array of used counters must be kept for decryption."
        print "It should not be reused for further encryptions with the same key "
        print "\nThe original message of length %d is:\n%s" % (len(message), message)
        print "\nThe encrypted message in hexadecimal presentation of length %d is:\n%s" % (len(hexCipher), hexCipher)
        # print "\nThe encrypted message with unencrypted secret is:\n%s" % (binascii.hexlify(secret+ciphertext)) 
        self.logCTRencryption(message, key, secret, hexCipher)
        decryptedtext = self.ctr_decrypt(secret + ciphertext, key)
        print "\nThe decrypted message is:\n%s" % (decryptedtext)
        self.logCTRdecryption(secret + ciphertext, message, decryptedtext)

    def ctr_decrypt(self, cipherPlusSecret, key):
        secret = cipherPlusSecret[:Cipher.BS]
        self._reset_counter_callback_state(secret)
        cipher = AES.new(key, AES.MODE_CTR, counter = self._decrypt_counter_callback)
        ciphertext = cipherPlusSecret[Cipher.BS:] # we didn't encrypt the secret, so don't decrypt it
        return cipher.decrypt(ciphertext)

    def logCTRencryption(self, message, key, secret, hexCipher):
        logger.info("\noriginal message:\n" + message + "\n\nkey:\n" + key + "\n\nrandom secret in hexadecimal presentation:\n" + binascii.hexlify(secret) + "\n\nmode:\nCTR")
        logger.info("\ncounters:\n" + str(self.counters))
        logger.info("\nThe encrypted message in hexadecimal presentation of length %d is:\n%s" % (len(hexCipher), hexCipher)) 

    def logCTRdecryption(self, cipherPlusSecret,  message, decryptedtext):
        logger.info("\nsecret plus cipher in hexadecimal presentation:\n" + binascii.hexlify(cipherPlusSecret))
        binaryFile(binascii.hexlify(cipherPlusSecret))
        logger.info("\ndecrypted message == original message:\n" + str(decryptedtext == message))


if __name__ == '__main__':
    Cipher().parse_args()


#
#
#                          m    m      \           /      m    m   
#                      m            m   \    n    /   m            m
#                       m              m \  OOO  / m              m
#                         m              m\/ Ö \/m              m
#                            m             mÖÖÖm            m
#                                 m    m    ÖÖÖ    m    m
#                                    m   m   Ö   m   m
#                           m               /Ö\              m
#                       m                  / Ö \                 m
#                     m               m   !  Ö  !   m              m
#                      m          m       !  Ö  !       m          m
#                         m  m            !  Ö  !           m  m
#                                        /   Ö   \
#                                            Ö
#                                            Ö
#                                            Ö
#                                            Ö
#                                            Ö
#
#