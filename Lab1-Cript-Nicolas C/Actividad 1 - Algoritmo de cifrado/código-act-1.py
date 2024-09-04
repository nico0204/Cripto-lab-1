import sys

def cifrar_cesar(texto, corrimiento):
    texto_cifrado = ""

    for caracter in texto:
        if caracter.isalpha():
            ascii_valor = ord(caracter)

            if caracter.isupper():
                nuevo_ascii = ((ascii_valor - 65 + corrimiento) % 26) + 65
            else:
                nuevo_ascii = ((ascii_valor - 97 + corrimiento) % 26) + 97

            caracter_cifrado = chr(nuevo_ascii)
        else:
            caracter_cifrado = caracter
        
        texto_cifrado += caracter_cifrado

    return texto_cifrado

if len(sys.argv) != 3:
    sys.exit(1)

texto_original = sys.argv[1]
corrimiento = int(sys.argv[2])
texto_cifrado = cifrar_cesar(texto_original, corrimiento)
print(texto_cifrado)
