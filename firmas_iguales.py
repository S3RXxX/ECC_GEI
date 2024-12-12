# Sacar la llave privada cuando firmas número aleatorio

import os
import sympy as sp
from ecpy.curves import Point, Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA

def generate_keypair(curve,Q, d):
    public_key = ECPublicKey(Q)
    private_key = ECPrivateKey(d, curve)
    return private_key, public_key

def do_sign(message=b""):
    k = 373
    cv   = Curve.get_curve('secp256k1')
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
    s1 = do_sign(message=b'aaa')
    s2 = do_sign(message=b'bbb')
    print(s1)
    print(s2)
    