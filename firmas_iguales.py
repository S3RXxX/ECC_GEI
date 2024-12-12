# Sacar la llave privada cuando firmas número aleatorio

import os
import sympy as sp
from ecpy.curves import Point, Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
from pyasn1.codec.der.decoder import decode
from pyasn1.type.univ import Sequence

def read_ASN(hex_string):
    # Convert the hex string to bytes
    encoded_bytes = bytes.fromhex(hex_string)
    
    # Decode the ASN.1 data
    decoded_data, _ = decode(encoded_bytes, asn1Spec=Sequence())
    
    # Process the decoded data as needed
    return int(decoded_data[0]), int(decoded_data[1])


def do_sign(message=b"", cv=Curve.get_curve('secp256k1')):
    k = 373
    
    pu_key = ECPublicKey(Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
                        0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
                        cv))
    pv_key = ECPrivateKey(0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5,
                    cv)


    signer = ECDSA()
    sig = signer.sign_k(message,pv_key, k=k)
    assert(signer.verify(message,sig,pu_key))

    return sig

if __name__=="__main__":
    m1 = b'aaa'
    m2 = b'bbb'
    cv   = Curve.get_curve('secp256k1')
    sign1 = do_sign(message=m1, cv=cv)
    sign2 = do_sign(message=m2, cv=cv)

    # utilitzem notació diferent per no confondre f1, f2
    # f1 --> r; f2 --> s
    r1, s1 = read_ASN(sign1.hex())
    r2, s2 = read_ASN(sign2.hex())
    assert(r1==r2)
    r = r1
    # depen de la curva (canviar a var)
    n = cv.order
    k = sp.mod_inverse(s2-s1, n) * (int(m2.hex(), 16) - int(m1.hex(), 16))%n
    print(f"Número aleatorio encontrado: {k}")

    # se puede hacer con s1, m1 o con s2, m2
    d1 = (s1*k-int(m1.hex(), 16))*sp.mod_inverse(r, n) %n
    d2 = (s2*k-int(m2.hex(), 16))*sp.mod_inverse(r, n) %n
    assert(d2==d1)
    d = d1
    print(f"Llave privada encontrada (d): {hex(d)}")


    
    