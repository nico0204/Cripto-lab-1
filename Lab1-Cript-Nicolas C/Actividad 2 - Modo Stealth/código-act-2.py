import sys
import time
import struct
from scapy.all import *

def send_icmp_requests(target_ip, input_text):
    # Parse the input text to get individual characters
    characters = list(input_text)

    # Initialize Identifier and Sequence Number
    identifier = 1
    sequence_number = 1
    for char in characters:
        # Create the ICMP packet
        icmp_packet = IP(dst=target_ip) / ICMP(type=8, id=identifier, seq=sequence_number)
        # Build the Data field as specified
        timestamp = int(time.time() * 10**9)  # Unix Epoch Time in nanoseconds
        data_field = struct.pack("!Q", timestamp) + char.encode() + b'\x00' * 7 + bytes(range(0x10, 0x38))
        icmp_packet = icmp_packet / Raw(load=data_field)
        # Send the ICMP packet using send() and print the default send() output
        send(icmp_packet)

       # Increment Sequence Number
        sequence_number += 1
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python icmp_sender.py <cadena de texto>")
    else:
        target_ip = "192.168.0.246"
        input_text = sys.argv[1]
        send_icmp_requests(target_ip, input_text)
