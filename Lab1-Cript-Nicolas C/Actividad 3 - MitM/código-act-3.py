import sys
import enchant
from scapy.all import *
from termcolor import colored

def decrypt_cesar(data, shift):
    decrypted = ""
    for char in data:
        if char.isalpha():
            shifted_char = chr(((ord(char.lower()) - ord('a') - shift) % 26) + ord('a'))
            decrypted += shifted_char.upper() if char.isupper() else shifted_char
        else:
            decrypted += char
    return decrypted

def is_english_or_spanish_word(word):
    # Verifica si una palabra es una palabra en inglés o español
    english_dict = enchant.Dict("en_US")
    spanish_dict = enchant.Dict("es_ES")
    return english_dict.check(word.lower()) or spanish_dict.check(word.lower())

def main(file_path):
    try:
        packets = rdpcap(file_path)
        filtered_packets = [pkt for pkt in packets if pkt.haslayer(ICMP) and pkt[IP].dst == "192.168.0.246"]

        best_shift = None
        best_decrypted_message = ""

        for shift in range(1, 27):
            decrypted_chars = []

            for pkt in filtered_packets:
                data_hex = pkt[Raw].load.hex()
                ninth_char_hex = data_hex[16:18]
                ninth_char_ascii = chr(int(ninth_char_hex, 16))
                decrypted_data = decrypt_cesar(ninth_char_ascii, shift)
                decrypted_chars.append(decrypted_data)

            output = ''.join(decrypted_chars)

            if best_shift is None or len(output) > len(best_decrypted_message):
                best_shift = shift
                best_decrypted_message = output

        for shift in range(27):
            decrypted_chars = []

            for pkt in filtered_packets:
                data_hex = pkt[Raw].load.hex()
                ninth_char_hex = data_hex[16:18]
                ninth_char_ascii = chr(int(ninth_char_hex, 16))
                decrypted_data = decrypt_cesar(ninth_char_ascii, shift)
                decrypted_chars.append(decrypted_data)

            output = ''.join(decrypted_chars)
            output_with_iteration = f"{shift - 1}\t{output}"

            if shift == best_shift:
                print(colored(output_with_iteration, 'green'))
            else:
                print(output_with_iteration)

        decrypted_message = ' '.join(best_decrypted_message.split())
        words = decrypted_message.split()
        meaningful_words = [word for word in words if is_english_or_spanish_word(word)]

        if meaningful_words:
            print("\nMensaje más probable (en inglés o español):")
            print(colored(decrypted_message, 'green'))

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py pcapng_file")
    else:
        pcapng_file = sys.argv[1]
        main(pcapng_file)
