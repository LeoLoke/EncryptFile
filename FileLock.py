# Author: Rodrigo Graca

# Cryptography and password handling
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import pbkdf2_hmac
from getpass import getpass

# Parse command line arguments
import argparse
import textwrap

# Regex for password validation
from re import search

# Interface with the os and filesystem
from os.path import getsize, splitext, isfile
from os import remove, rename
from sys import exit
from platform import system
import subprocess
import time

# Store file attribute lengths
import struct

# Enum for easier readability
from enum import Enum

# Compression algorithms
import lzma
import bz2
import gzip

# Bytes
AES_KEY_LENGTH = 32
AES_SALT_LENGTH = 256
DEFAULT_CHUNKSIZE = 128000  # 1000 bytes = 1 kilobyte
MAC_LEN = 16
HEADER_LEN = 16
NONCE_LEN = 32

# How many times the password derive function iterates
HMAC_ITER = 10000000

# Struct Def
STRUCT_DEF = '>Q'  # Max file size to store: 9223.37 Petabytes

# Name of intermediate file
TEMP_FILE_NAME = 'file.temp'

# Number of passes to securely remove file
PASSES = 20

# Define encoding when going from str to bytes
DEFAULT_ENCODING = 'utf-16'


# Enum to select compression algorithms
class CompAlgo(Enum):
    NONE = 1
    GZIP = 2
    LZMA = 3
    BZ2 = 4


# Default algorithm
DEFAULT_ALGO = CompAlgo.NONE

# Global options passed from the args
options = {'verbose': False,
           'secureDel': False,
           'clean': False}


def helpText():
    return """
    =========================================================================================
    |    Hello! Welcome to FileLock. This program features both encryption and decryption   | 
    |         of files. It supports AES-256 symmetric encryption and features               |
    |                               compression algorithms                                  |
    =========================================================================================
    
             Defaults
                # Bytes
                AES_KEY_LENGTH = """ + str(AES_KEY_LENGTH) + """
                ES_SALT_LENGTH = """ + str(AES_SALT_LENGTH) + """
                DEFAULT_CHUNKSIZE = """ + str(DEFAULT_CHUNKSIZE) + """   # 1000 bytes = 1 kilobyte
                MAC_LEN = """ + str(MAC_LEN) + """
                HEADER_LEN = """ + str(HEADER_LEN) + """
                NONCE_LEN (IV) = """ + str(NONCE_LEN) + """
                
                # How many times the password derive function iterates
                HMAC_ITER = """ + str(HMAC_ITER) + """
                
                # Number of passes to securely remove file
                PASSES = """ + str(PASSES) + """
                
                # Default Compression algorithm
                DEFAULT_ALGO = """ + str(DEFAULT_ALGO) + """
                
                # Struct Def
                STRUCT_DEF = '""" + STRUCT_DEF + """'  # Max file size to store: 9223.37 Petabytes
                
                # Define encoding when going from str to bytes
                DEFAULT_ENCODING = """ + DEFAULT_ENCODING + """
                
                Passcode
                    Should have at least one number.
                    Should have at least one uppercase and one lowercase character.
                    Should have at least one special symbol.
                    Should be between 10 to 20 characters long.
    -----------------------------------------------------------------------------------------
    """


def setupArgParse():
    global options

    # Setup the argparse to handle command line arguments
    parser = argparse.ArgumentParser(
        description=(textwrap.dedent(helpText())),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Either Encrypt or Decrypt has to be selected, but not both at once
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', '--encrypt', help='File to encrypt', metavar='file')
    group.add_argument('-d', '--decrypt', help='File to decrypt', metavar='file')
    group.required = True

    # Setup settings
    parser.add_argument('-a', '--algo', help='Select from gzip, lzma, and bz2. Omit for no compression', metavar='algo',
                        default='none',
                        nargs='?')
    parser.add_argument('-c', '--chunk',
                        help=('Size in bytes of chunk (Default: ' + str(DEFAULT_CHUNKSIZE / 1000) + ' kilobytes)'),
                        default=DEFAULT_CHUNKSIZE,
                        metavar='size',
                        type=int)

    parser.add_argument('-g', '--gen', action='store_true', help='Generate random key for passcode')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display more detailed information on operations',
                        default=(options['verbose']))

    # Secure delete, be careful can cause irreparable damage
    parser.add_argument('-s', '--secure', action='store_true',
                        help='Use Sdelete and select number of rounds to securely write over data (Default: True)',
                        default=(options['secureDel']))
    parser.add_argument('--clean', action='store_true',
                        help='Destroy original file after encrypting it (Default: False)',
                        default=(options['clean']))
    return parser


def run():
    # Setup argparse
    parser = setupArgParse()

    # Grab passed arguments
    args = parser.parse_args()

    # Set global options
    options['verbose'] = args.verbose
    options['secureDel'] = args.secure
    options['clean'] = args.clean

    # Determine if to encrypt or decrypt
    if args.encrypt:

        # Make sure the file exists before proceeding
        fileToEncrypt = args.encrypt
        if isfile(fileToEncrypt):
            print('File found!')
        else:
            raise FileNotFoundError('The file %s cannot be located' % fileToEncrypt)

        if getsize(fileToEncrypt) <= 0:
            raise EOFError('The file %s is empty!' % fileToEncrypt)

        # Generate random password or retrieve from user
        if not args.gen:
            passcode = getValidatedPass()
        else:
            passcode = get_random_bytes(64)

        # Set compression algorithm or specify NONE if empty
        algo = CompAlgo.NONE
        if not args.algo:
            print('No algo')
        elif args.algo.lower() == 'bz2':
            algo = CompAlgo.BZ2
        elif args.algo.lower() == 'lzma':
            algo = CompAlgo.LZMA
        elif args.algo.lower() == 'gzip':
            algo = CompAlgo.GZIP

        print(algo)

        # Begin processing file
        encryptFile(fileToEncrypt, passcode=passcode, algo=algo, chunksize=args.chunk)
    elif args.decrypt:

        # Make sure the file exists before proceeding
        fileToDecrypt = args.decrypt
        if isfile(fileToDecrypt):
            print('File found!')
        else:
            raise FileNotFoundError('The file: %s cannot be located' % fileToDecrypt)

        # Ensure file is correct format
        if not splitext(fileToDecrypt)[1] == ".encrypted":
            raise FileNotFoundError('The file: %s is not of [.encrypted] file type' % fileToDecrypt)

        if getsize(fileToDecrypt) <= 0:
            raise EOFError('The file %s is empty!' % fileToDecrypt)

        # Get the passcode from the user and encode it into bytes
        passcode = getpass(prompt='Passcode: ')
        passcode = passcode.encode(DEFAULT_ENCODING)

        # Set compression algorithm or specify NONE if empty
        algo = CompAlgo.NONE
        if not args.algo:
            print('No algo')
        else:
            if args.algo.lower() == 'bz2':
                algo = CompAlgo.BZ2
            elif args.algo.lower() == 'lzma':
                algo = CompAlgo.LZMA
            elif args.algo.lower() == 'gzip':
                algo = CompAlgo.GZIP

        print(algo)

        # Begin processing file
        decryptFile(fileToDecrypt, passcode=passcode, algo=algo, chunksize=(args.chunk))
    else:

        # Display help info
        parser.print_help()


def encryptFile(inFilename, outFilename=None, passcode=get_random_bytes(AES_KEY_LENGTH), chunksize=DEFAULT_CHUNKSIZE,
                algo=DEFAULT_ALGO):

    # Get password-derived key
    salt = get_random_bytes(AES_SALT_LENGTH)
    aes_key = pbkdf2_hmac('sha256', passcode, salt, HMAC_ITER)

    # Initialize AES Cipher and update header
    # Return random bytes for header and set up EAX mode with random 256 bit IV, MAC length 128 bits
    header = get_random_bytes(HEADER_LEN)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=(get_random_bytes(NONCE_LEN)), mac_len=MAC_LEN)
    aes_cipher.update(header)

    if not outFilename:
        outFilename = str(splitext(inFilename)[0]) + '.encrypted'

    fileName = inFilename
    fileSize = 0

    # Get the input file's size
    try:
        fileSize = getsize(inFilename)
    except OSError:
        print("File '%s' does not exists or could not be accessed" % inFilename)
        exit(1)

    # Begin process timer
    start = time.time()

    # Compress the file if specified
    if not algo == CompAlgo.NONE:
        print('Compressing file...')
        compressFile(algo, inFilename)
        inFilename = TEMP_FILE_NAME
        print('Compressed!')

    # Encrypt file
    with open(inFilename, 'rb') as inFile, open(outFilename, 'wb') as encrypted:
            print('Encrypting file...')
            _encryptFile(encrypted, inFile, fileName, fileSize, header, aes_cipher, chunksize, salt)
            print('Encrypted!')

    # Cleanup after ourselves
    if not algo == CompAlgo.NONE:
        print('Deleting temp file...')
        if not removeSecure(TEMP_FILE_NAME):
            print('Could not preform secure delete')
            # TODO Make into option if user should handle deleting
            remove(TEMP_FILE_NAME)
        print('Deleted!')

    # Calculate how long the process took
    elapsed_time = time.time() - start
    m, s = divmod(elapsed_time, 60)
    s = round(s, 1)
    print('Took ' + str(m) + ' minutes and ' + str(s) + ' seconds')


def decryptFile(inFilename, passcode, outFilename='test', chunksize=DEFAULT_CHUNKSIZE, algo=DEFAULT_ALGO):

    finalName = outFilename

    # If there is a compression algo, use temp file
    if not algo == CompAlgo.NONE:
        outFilename = TEMP_FILE_NAME

    # Begin decryption
    start = time.time()
    with open(inFilename, 'rb') as encrypted, open(outFilename, 'wb') as decrypted:
        print('Decrypting file...')
        fileName = _decryptFile(encrypted, decrypted, passcode, chunksize)
        if fileName:
            finalName = fileName
        else:
            finalName = outFilename
        print('Decrypted!')

    # Rename file to correct
    if not algo == CompAlgo.NONE:
        if not finalName:
            finalName = 'Decoded-' + splitext(inFilename)[0]
        print('Decompressing file...')
        decompressFile(algo, outFilename, finalName)
        print('Decompressed!')

    # If a original filename was stored, use it
    try:
        if outFilename not in finalName:
            rename(outFilename, finalName)
    except (FileExistsError, FileNotFoundError):
        print("File already exists, aborted renaming")

    # TODO Verify file size to ensure all original bits are included

    elapsed_time = time.time() - start
    m, s = divmod(elapsed_time, 60)
    s = round(s, 1)
    print('Took ' + str(m) + ' minutes and ' + str(s) + ' seconds')


def removeSecure(filePath, passes=PASSES):

    # Attempt to delete using secure delete as set
    if options['secureDel']:

        # Run sdelete.exe on file with set passes, will take a bit of time and disk write bandwidth for large files
        if system() == 'Windows':
            sdelete = subprocess.Popen(['sdelete.exe', '-r', '-nobanner', '-p', str(passes), filePath],
                                       stdout=subprocess.PIPE, shell=True)
            output = sdelete.stdout.read()
            sdelete.wait(15)
            sdelete.kill()
            if 'No files/folders found that match' in str(output):
                return False
        return True
    return False


def decompressFile(algo, inFilename, outFilename):

    # Decompress file based on algorithm selected and move output to final file
    open(outFilename, 'a').close()
    if algo == CompAlgo.GZIP:
        with open(outFilename, 'wb') as f_out, gzip.open(inFilename, 'rb') as f_in:
                copyFiles(f_in, f_out, operation='decompressed')
    if algo == CompAlgo.BZ2:
        with open(outFilename, 'wb') as f_out, bz2.BZ2File(inFilename, 'rb', compresslevel=9) as f_in:
                copyFiles(f_in, f_out, operation='decompressed')
    if algo == CompAlgo.LZMA:
        with open(outFilename, 'wb') as f_out, lzma.open(inFilename, 'rb') as f_in:
                copyFiles(f_in, f_out, operation='decompressed')

    # Attempt to delete securely
    # TODO Move secure delete check to removeSecure() : Also move this check to decryptFile()
    print('Deleting temp file...')
    if not removeSecure(TEMP_FILE_NAME):
        print('Could not preform secure delete')
        remove(TEMP_FILE_NAME)
    print('Deleted!')


def compressFile(algo, inFilename):
    # Compress file based on algorithm selected and move output to temp file
    open(TEMP_FILE_NAME, 'a').close()
    if algo == CompAlgo.GZIP:
        with open(inFilename, 'rb') as f_in, gzip.open(TEMP_FILE_NAME, 'wb') as f_out:
                copyFiles(f_in, f_out)
    elif algo == CompAlgo.BZ2:
        with open(inFilename, 'rb') as f_in, bz2.BZ2File(TEMP_FILE_NAME, 'wb', compresslevel=9) as f_out:
                copyFiles(f_in, f_out)
    elif algo == CompAlgo.LZMA:
        with open(inFilename, 'rb') as f_in, lzma.open(TEMP_FILE_NAME, 'wb') as f_out:
                copyFiles(f_in, f_out)

    tempSize = getsize(TEMP_FILE_NAME)
    fileSize = getsize(inFilename)
    print('Compression ratio: ' + str(round(tempSize / fileSize, 1) * 100) + '%')


def _encryptFile(encrypted, inFile, fileName, fileSize, header, aes_cipher, chunksize, salt):

    # TODO Remove struct line from here, already stored encrypted
    # Write data useful for decrypting later on
    encrypted.write(struct.pack(STRUCT_DEF, fileSize))
    encrypted.write(aes_cipher.nonce)
    encrypted.write(header)
    encrypted.write(b' ' * MAC_LEN)  # Empty bytes to write over later on, MAC calculated at end
    encrypted.write(salt)

    bytesRead = 0
    totalBytes = getsize(inFile.name)

    # Encode file name to be read back and applied later
    fileName = bytes(fileName, DEFAULT_ENCODING)

    # Allows for variable file name sizes
    encrypted.write(aes_cipher.encrypt(struct.pack(STRUCT_DEF, len(fileName))))
    encrypted.write(aes_cipher.encrypt(fileName))

    # Read and encrypt in predefined chunk sizes
    while True:

        chunk = inFile.read(chunksize)

        if options['verbose']:
            bytesRead += len(chunk)
            percentage = round(bytesRead / totalBytes * 100, 1)

            # \r so only one line is overwritten each update
            if percentage < 100:
                print((str(percentage) + '% encrypted'), end='\r')
            else:
                print('                  ', end='\r')

        if len(chunk) == 0:
            break

        encrypted.write(aes_cipher.encrypt(chunk))

    # Write MAC address to empty bytes at correct location
    MAC = aes_cipher.digest()
    encrypted.seek(struct.calcsize(STRUCT_DEF) + NONCE_LEN + HEADER_LEN)
    encrypted.write(MAC)


def _decryptFile(encrypted, decrypted, passcode, chunksize):

    # Grab needed components for decryption
    origsize = struct.unpack(STRUCT_DEF, encrypted.read(struct.calcsize(STRUCT_DEF)))[0]
    nonce = encrypted.read(NONCE_LEN)
    header = encrypted.read(HEADER_LEN)
    MAC = encrypted.read(MAC_LEN)
    salt = encrypted.read(AES_SALT_LENGTH)

    # Get password-derived key
    aes_key = pbkdf2_hmac('sha256', passcode, salt, HMAC_ITER)

    # Setup AES Cipher and update header
    aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce, mac_len=MAC_LEN)
    aes_cipher.update(header)

    fileName = None

    # Will throw error if passcode incorrect
    try:

        # Grab the file name for later
        fileNameLen = struct.unpack(
            STRUCT_DEF, aes_cipher.decrypt(
                encrypted.read(struct.calcsize(STRUCT_DEF)))
        )[0]

        fileName = aes_cipher.decrypt(encrypted.read(fileNameLen)).decode(DEFAULT_ENCODING)
    except (OverflowError, MemoryError):
        print('Passcode incorrect')
        exit(1)

    bytesRead = 0
    totalBytes = getsize(encrypted.name)

    print('NAME: ' + str(fileName))

    # Read and decrypt in predefined chunk sizes
    while True:

        chunk = encrypted.read(chunksize)

        if len(chunk) == 0:
            break

        if options['verbose']:
            bytesRead += len(chunk)
            percentage = round(bytesRead / totalBytes * 100, 1)

            # \r so only one line is overwritten each update
            if percentage < 100:
                print((str(percentage) + '% decrypted'), end='\r')
            else:
                print('                  ', end='\r')

        chunk = aes_cipher.decrypt(chunk)
        decrypted.write(chunk)

    # Verify file integrity
    try:
        aes_cipher.verify(MAC)
    except ValueError:
        print('MAC check failed!')
        exit(1)

    print("File Verified! It's untouched.")
    return fileName


# Copy file implementation with verbose percentage completed option
def copyFiles(src, dst, chunksize=DEFAULT_CHUNKSIZE, operation='compressed'):
    bytesRead = 0
    totalBytes = getsize(src.name)

    while True:

        chunk = src.read(chunksize)

        if not chunk:
            break

        if options['verbose']:
            bytesRead += len(chunk)
            percentage = round(bytesRead / totalBytes * 100, 1)

            if percentage < 100:
                print((str(percentage) + '% ' + operation), end='\r')
            else:
                print('                  ', end='\r')

        dst.write(chunk)


def getValidatedPass():
    valid = False

    passcode = ''

    # Check to make sure the passcode is secure
    while not valid:
        passcode = getpass(prompt='Passcode: ')
        print()
        if len(passcode) < 6 or len(passcode) > 20:
            print('Password length needs to be between: 6 - 20 characters')
        elif not search('[a-z]', passcode):
            print('Password requires: Lowercase letter')
        elif not search('[0-9]', passcode):
            print('Password requires: Number')
        elif not search('[A-Z]', passcode):
            print('Password requires: Uppercase letter')
        elif not search('[$#@]', passcode):
            print('Password requires: Special symbol ($#@)')
        elif search('\s', passcode):
            print('No spaces in the passcode are allowed')
        else:
            valid = True
            print('Valid passcode')

    return passcode.encode(DEFAULT_ENCODING)


if __name__ == '__main__':
    run()
