# import libraries
import argparse
import os
import rsa
import binascii

# men-generate key pair
def generateKeyPair():
    (publicKey, privateKey) = rsa.newkeys(2048)

    with open('private_key.key', 'wb') as kf:
        kf.write(privateKey.save_pkcs1('PEM'))

    with open('public_key.key', 'wb') as kf:
        kf.write(publicKey.save_pkcs1('PEM'))

    return True

# membuka sebuah file
def openFile(file):
    keyFile = open(file, 'rb')
    keyData = keyFile.read()
    keyFile.close()

    return keyData

# membuat digital signature sebuah dokumen
def signFile(input_file: str, output_file: str = None):
    if not output_file:
        output_file = (os.path.splitext(input_file)[0]) + "_signed.pdf"

    privateKey = rsa.PrivateKey.load_pkcs1(openFile('private_key.key'))
    document = openFile('sample.pdf')
    signature = rsa.sign(document, privateKey, 'SHA-256')

    s = open('signature.pfx','wb')
    s.write(signature)

    with open(output_file, 'wb') as f:
        f.write(document)
    
    #embed signature
    # with open(output_file, 'wb') as f:
    #     f.write(document + signature)
    
    # hashResult = rsa.compute_hash(document, 'SHA-256') 
    # print("\nHash Value Size:", len(hashResult)*8)

    summary = { "Input File": input_file, "Output File": output_file, "Signature": signature, "Signature HEX": binascii.hexlify(signature)}
    print("\n\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    return True

# untuk verifikasi dgital signature
def verify():
    publicKey = rsa.PublicKey.load_pkcs1(openFile('public_key.key'))
    document = openFile('sample_signed.pdf')
    signature = openFile('signature.pfx')
    try:
        rsa.verify(document,signature,publicKey)
        print("Verified: YES")
    except:
        print("Verified: NO")

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
    parser.add_argument('-g', dest='generate', action="store_true")
    parser.add_argument('-i', dest='input_path', type=is_valid_path)
    parser.add_argument('-v', dest='verify', action="store_true")
    path = parser.parse_known_args()[0].input_path
    if path and os.path.isfile(path):
        parser.add_argument('-o', dest='output_file', type=str)
    args = vars(parser.parse_args())

    return args


# mengeksekusi program
if __name__ == '__main__':
    args = parse_args()
    if args['generate'] == True:
        generateKeyPair()
    elif args['verify'] == True:
        verify()
    else:
        if os.path.isfile(args['input_path']):
            signFile(input_file=args['input_path'], output_file=args['output_file'])
