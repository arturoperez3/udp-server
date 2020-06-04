import ast
import sys
import zlib
import time
import getopt
import socket
import logging
import hashlib
import threading


def udp_server(argv):

    print("Server start up . . .")

    # Handle command line arguments
    (p, d, key_dictionary, binary_dictionary,
        checksum_dictionary) = parse_command_line(argv)

    # Set up our 2 loggers
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    v_logger = setup_logger(formatter, 'verification_logger', 
        'verification_failures.log')
    c_logger = setup_logger(formatter, 'checksum_logger', 
        'checksum_failures.log')

    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind socket to port
    server_address = ('127.0.0.1', int(p))
    sock.bind(server_address)

    print ("Server is running: Press ^C to end.")
    try:
        while True:
            
            data, address = sock.recvfrom(4096)

            packet_validation(data, key_dictionary, binary_dictionary, checksum_dictionary, 
                c_logger, v_logger, d)
    except KeyboardInterrupt:
        print('Server shut down.')

    sock.close()
    sys.exit(0)


def parse_command_line(argv):
    # Parse command line arguments
    short_options = "d:p:"
    long_options = ["keys=", "binaries="]
    try:
        opts, args = getopt.getopt(argv, short_options, long_options)
    except getopt.GetoptError:
        print('invalid argument passed')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-d':
            d = arg
        elif opt in ('-p'):
            p = arg
        elif opt in ("--keys"):
            keys = arg
        elif opt in ("--binaries"):
            binaries = arg

    # Take inputs and place into dictionaries
    keys = ast.literal_eval(keys)
    binaries = ast.literal_eval(binaries)

    # Parse provided keys, place into dictionary
    # Build checksum dictionary
    key_dictionary = {}
    checksum_dictionary = {}
    for key in keys:
        with open(keys[key], mode='rb') as file: 
            key_content = file.read()

        key_content = (key_content.hex())
        public_key = key_content[6:]
        exponent = key_content[0:6]
        key_dictionary.update({key: [public_key, exponent]})
        checksum_dictionary.update({key: {0: 0}})

    # Parse provided binaries, place into dictionary
    binary_dictionary = {}
    for binary in binaries:
        with open(binaries[binary], mode='rb') as image: 
            binary_content = image.read()
            binary_dictionary.update({binary : binary_content})

    return p, d, key_dictionary, binary_dictionary, checksum_dictionary


def packet_validation(packet_data, key_dictionary, binary_dictionary, 
    checksum_dictionary, c_logger, v_logger, d):

    ##### Parse Required Information #####
    # Convert data from bytes to hexadecimal string
    packet_data_hex = packet_data.hex()

    # 4 bytes, convert to hexadecimal integer
    packet_id = hex(int(packet_data_hex[:8], 16))

    # 4 bytes, convert to hexadecimal integer
    packet_sequence_number = int(packet_data_hex[8:16], 16)

    # 2 bytes, convert to hexadecimal integer
    xor_key = int(packet_data_hex[16:20] + packet_data_hex[16:20], 16)

    # 64 bytes, convert to hexadecimal integer
    rsa = int(packet_data_hex[-128:], 16)

    ##### Verify Checksum #####
    # Use start and end to denote where we currently are in the checksum body
    # Each checksum is 4 bytes long (8 hexadecimal characters)
    checksum_start = 24
    checksum_end = 32
    number_of_checksums = int(packet_data_hex[20:24], 16)
    checksum = checksum_dictionary[packet_id]
    for x in range(number_of_checksums):

        # Calculate next checksum expected in the packet
        binary = packet_id
        checksum, packet_sequence_number = calculate_checksum(
            packet_sequence_number, checksum, binary_dictionary, binary)
        # Update checksum dictionary
        checksum_dictionary[packet_id] = checksum

        # Hexify local checksum
        hex_checksum = hex(checksum[packet_sequence_number] ^ xor_key)

        # If checksum is less than 8 characters, append 0's to the front
        while len(hex_checksum) < 10:
            hex_checksum = hex_checksum[0:2] + "0" + hex_checksum[2:]

        # Compare calculated local checksum to checksum received in packet
        if hex_checksum[2:] != packet_data_hex[checksum_start:checksum_end]:
            #print ("CHECKSUM WRONG: " + str(packet_sequence_number))
            t = threading.Thread(target=checksum_logging, args = 
                (c_logger, packet_id, int(packet_data_hex[8:16],16), 
                packet_sequence_number,
                packet_data_hex[checksum_start:checksum_end], 
                hex_checksum[2:], d))
            t.start()

        # Go to next checksum in packet
        checksum_start = checksum_end
        checksum_end += 8

    ##### Verify RSA SHA 512 Signature #####
    # Get all the data from the packet minus the RSA 512 SHA 256 signature 
    packet_data_to_hash = packet_data[0:len(packet_data)-64]

    # Take the hash, convert to hexadecimal
    local_hash = (hashlib.sha256(packet_data_to_hash)).hexdigest()

    # Decrypt RSA signature from packet by using the public key and exponent
    public_key = int(key_dictionary.get(packet_id)[0],16)
    exponent = int(key_dictionary.get(packet_id)[1],16)
    packet_hash = pow(rsa, exponent, public_key)

    # Compare calculated local hash to the decrypted hash received in packet
    if hex(packet_hash)[65:] != local_hash[2:]:
        #print ("HASH WRONG: " + str(packet_sequence_number))
        t = threading.Thread(target=verification_logging, args = 
            (v_logger, packet_id, 
            int(packet_data_hex[8:16],16),
            hex(packet_hash)[65:], 
            local_hash[2:], d))
        t.start()


def calculate_checksum(packet_sequence_number, checksum, 
    binary_dictionary, binary):
    local = 0
    packet_sequence_number += 1

    # Handle out-of-order sequences 
    try:
        local = checksum[packet_sequence_number-1]
        return {packet_sequence_number: ((zlib.crc32(binary_dictionary.get(binary),
            local) & 0xffffffff))}, packet_sequence_number
    except KeyError:
        # If out-of-order, calculate checksum up to packet sequence number of out-of-order packet
        # This is not very fast. But it was the only way I found to verify out-of-order checksums
        for x in range(packet_sequence_number):
            local = ((zlib.crc32(binary_dictionary.get(binary),local) & 0xffffffff))
        
    return {packet_sequence_number: local}, packet_sequence_number


def checksum_logging(c_logger, packet_id, packet_sequence_number, iteration, 
    packet_checksum, checksum, d):
    time.sleep(int(d))
    c_logger.info(packet_id + "\n" 
            + str(packet_sequence_number) + "\n"
            + str(iteration) + "\n"
            + str(packet_checksum) + "\n"
            + str(checksum) + "\n\n")


def verification_logging(v_logger, packet_id, packet_sequence_number, 
    packet_hash, local_hash, d):
    time.sleep(int(d))
    v_logger.info(packet_id + "\n"
            + str(packet_sequence_number) + "\n"
            + str(packet_hash) + "\n"
            + str(local_hash) + "\n\n")


# Set up our 2 loggers
def setup_logger(formatter, name, log_file, level=logging.INFO):
    handler = logging.FileHandler(log_file)        
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


if __name__ == "__main__":
   udp_server(sys.argv[1:])
