# import libraries
import OpenSSL
import random
from PDFNetPython3.PDFNetPython import *
from typing import Tuple

# men-generate key pair
def generateKeyPair(type, bits):
    pKey = OpenSSL.crypto.PKey()
    pKey.generate_key(type, bits)
    return pKey

# membuat self signed certificate
def createCertificate(pKey):
    certif = OpenSSL.crypto.X509()

    # menambahkan identity untuk certificate
    certif.get_subject().CN = "KIJ C 2022"
    certif.set_serial_number(random.randint(1, 100))

    # menambahkan expiration time
    certif.gmtime_adj_notBefore(0)
    certif.gmtime_adj_notAfter(1 * 365 * 24 * 60 * 60)
    certif.set_issuer((certif.get_subject()))

    # set public key dari certificate
    certif.set_pubkey(pKey)

    # sign certificate dengan key dan metode SHA-256
    certif.sign(pKey, 'sha256')  

    return certif


def loadFile():
    final = {}

    # men-generate key pair
    key = generateKeyPair(OpenSSL.crypto.TYPE_RSA, 1024)

    # menyimpan private key di file private_key.pem
    with open('.\static\private_key.pem', 'wb') as priv_key:
        priv_key_str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        priv_key.write(priv_key_str)
        final['Private Key'] = priv_key_str

    # menyimpan certificate di file certificate.cer
    certif = createCertificate(pKey = key)
    with open('.\static\certificate.cer', 'wb') as cer:
        cer_str = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certif)
        cer.write(cer_str)
        final['Self Signed Certificate'] = cer_str

    # menyimpan public key di file public_key.pem
    with open('.\static\public_key.pem', 'wb') as pub_key:
        pub_key_str = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, certif.get_pubkey())
        pub_key.write(pub_key_str)
        final['Public Key'] = pub_key_str

    # membuat file PKCS12 bernama keeper.pfx yang berisi private key dan certificate
    p12File = OpenSSL.crypto.PKCS12()
    p12File.set_privatekey(key)
    p12File.set_certificate(certif)
    open('.\static\keeper.pfx', 'wb').write(p12File.export())

    print("\n\n".join("{}:{}".format(i, j) for i, j in final.items()))

    return True