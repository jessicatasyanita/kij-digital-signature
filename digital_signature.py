# import libraries
import OpenSSL
import argparse
import os
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
    with open('.\private_key.pem', 'wb') as priv_key:
        priv_key_str = OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, key)
        priv_key.write(priv_key_str)
        final['Private Key'] = priv_key_str

    # menyimpan certificate di file certificate.cer
    certif = createCertificate(pKey=key)
    with open('.\certificate.cer', 'wb') as cer:
        cer_str = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, certif)
        cer.write(cer_str)
        final['Certificate'] = cer_str

    # menyimpan public key di file public_key.pem
    with open('.\public_key.pem', 'wb') as pub_key:
        pub_key_str = OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_PEM, certif.get_pubkey())
        pub_key.write(pub_key_str)
        final['Public Key'] = pub_key_str

    # membuat file PKCS12 bernama keeper.pfx yang berisi private key dan certificate
    p12File = OpenSSL.crypto.PKCS12()
    p12File.set_privatekey(key) 
    p12File.set_certificate(certif)
    open('.\keeper.pfx', 'wb').write(p12File.export())

    print("\n\n".join("{}:{}".format(i, j) for i, j in final.items()))

    return True


def sign_file(input_file: str, signatureID: str, xCoor: int, yCoor: int, output_file: str = None):

    if not output_file:
        output_file = (os.path.splitext(input_file)[0]) + "_signed.pdf"

    PDFNet.Initialize("demo:1667003327288:7ad3cf020300000000c9c4eac83c3783fe2559b0f726886b2600d0224d")
    doc = PDFDoc(input_file)

    sigField = SignatureWidget.Create(doc, Rect(xCoor, yCoor, xCoor+100, yCoor+50), signatureID)
    pg = doc.GetPage(1)
    pg.AnnotPushBack(sigField)

    sign_filename = os.path.dirname(os.path.abspath(__file__)) + "\signature.jpg"

    pk_filename = os.path.dirname(os.path.abspath(__file__)) + "\keeper.pfx"

    approval_field = doc.GetField(signatureID)
    approval_signature_digsig_field = DigitalSignatureField(approval_field)

    img = Image.Create(doc.GetSDFDoc(), sign_filename)
    found_approval_signature_widget = SignatureWidget(approval_field.GetSDFObj())
    found_approval_signature_widget.CreateSignatureAppearance(img)

    approval_signature_digsig_field.SignOnNextSave(pk_filename, '')

    opts = VerificationOptions(VerificationOptions.e_compatibility_and_archiving)
    opts.AddTrustedCertificate(pk_filename)
    results = doc.VerifySignedDigitalSignatures(opts)
    verified = ""
    if(results == 1):
        verified = "YES"
    elif(results == 0):
        verified = "NO"

    doc.Save(output_file, SDFDoc.e_incremental)
    summary = { "Input File": input_file, "Signature ID": signatureID,
                "Output File": output_file, "Signature File": sign_filename,
                "Certificate File": pk_filename, "Verified": verified
              }

    print("\n\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    return True

# memeriksa path dari file yang akan ditambahkan signature
def is_valid_path(path):
    if not path:
        raise ValueError(f"Invalid Path")
    if os.path.isfile(path):
        return path
    elif os.path.isdir(path):
        return path
    else:
        raise ValueError(f"Invalid Path {path}")

# define command untuk menjalankan program
def parse_args():
    parser = argparse.ArgumentParser(description="Available Options")
    parser.add_argument('-l', dest='load', action="store_true")
    parser.add_argument('-i', dest='input_path', type=is_valid_path)
    parser.add_argument('-s', dest='signatureID', type=str)
    parser.add_argument('-x', dest='xCoor', type=int)
    parser.add_argument('-y', dest='yCoor', type=int)
    path = parser.parse_known_args()[0].input_path
    if path and os.path.isfile(path):
        parser.add_argument('-o', dest='output_file', type=str)

    args = vars(parser.parse_args())

    return args


# mengeksekusi program
if __name__ == '__main__':
    args = parse_args()
    if args['load'] == True:
        loadFile()
    else:
        # jika file path valid
        if os.path.isfile(args['input_path']):
            sign_file( input_file=args['input_path'], signatureID=args['signatureID'], xCoor=int(args['xCoor']), yCoor=int(args['yCoor']), output_file=args['output_file'])
