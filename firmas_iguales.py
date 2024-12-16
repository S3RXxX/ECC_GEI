# Sacar la llave privada cuando firmas número aleatorio

import os
import sympy as sp
from ecpy.curves import Point, Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
from pyasn1.codec.der.decoder import decode
from pyasn1.type.univ import Sequence, Integer
from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.codec.der.encoder import encode
from math import sqrt
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def read_ASN(hex_string):
    # Convert the hex string to bytes
    encoded_bytes = bytes.fromhex(hex_string)
    
    # Decode the ASN.1 data
    decoded_data, _ = decode(encoded_bytes, asn1Spec=Sequence())
    
    # Process the decoded data as needed
    return int(decoded_data[0]), int(decoded_data[1])


def do_sign(message=b"", cv=Curve.get_curve('secp256k1'), pub_key=None):
    k = 373
    if not pub_key:
        pu_key = ECPublicKey(Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
                        0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
                        cv))
    pv_key = ECPrivateKey(0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5,
                    cv)


    signer = ECDSA()
    sig = signer.sign_k(message,pv_key, k=k)
    assert(signer.verify(message,sig,pu_key))

    return sig
def to_bytes(n):
    byte_length = (n.bit_length() + 7) // 8  # Minimum number of bytes to represent n
    # byte_length = 35
    return n.to_bytes(byte_length, byteorder='big')


class TwoElementSequence(Sequence):
    componentType = NamedTypes(
        NamedType('firstElement', Integer()),
        NamedType('secondElement', Integer())
    )

def list_to_asn1(data_list):
    # Ensure the input is a list with exactly 2 elements
    if len(data_list) != 2:
        raise ValueError("Input must be a list with exactly 2 elements")
    
    # Create an instance of the SEQUENCE
    asn1_obj = TwoElementSequence()
    asn1_obj.setComponentByName('firstElement', data_list[0])
    asn1_obj.setComponentByName('secondElement', data_list[1])
    
    # Encode the SEQUENCE into ASN.1 DER format
    encoded_data = encode(asn1_obj)
    return encoded_data

def read_certificate(filepath):
    with open(file=filepath, mode="rb") as cert_file:
        cert_data = cert_file.read()

    # Cargar el certificado X.509 desde los datos PEM
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert


# Verificar una firma ECDSA
def verify_ecdsa_signature(public_key, message, signature):
    ecdsa = ECDSA()
    # hashed_message = int.from_bytes(sha256(message).digest(), byteorder='big')
    return ecdsa.verify(message, signature, public_key)

if __name__=="__main__":
    Sergi=None

    # m1 = b'aaa'
    # m2 = b'bbb'
    # cv   = Curve.get_curve('secp256k1') #Curve.get_curve('secp521r1')
    # sign1 = do_sign(message=m1, cv=cv)
    # sign2 = do_sign(message=m2, cv=cv)

    # utilitzem notació diferent per no confondre f1, f2
    # f1 --> r; f2 --> s
    # r1, s1 = read_ASN(sign1.hex())
    # r2, s2 = read_ASN(sign2.hex())
    # print(len(str(r1)), len(str(s1)))


    
    # m1 = to_bytes(m1)
    # m2 = to_bytes(m2)

    # int(m2.hex(), 16)
    # int(m1.hex(), 16)

    ###################################
    ## k igual per 2 firmes ECDSA #####
    ###################################
    # m1 = 0x8708878e50041df55aeaf58e1ee03dc723aab45d36d47f4e1d49597b35aa6eb2f29b815b3131a4d8225610e909c4ca2f # b'aaa'
    # m2 = 0x47147e25d90562e96e978cff70ff1c208a482c28ebcc45d3552d62d4eb65c45ed0a7ed1b1c8f998ad9a7240e9bf12e9 # b'bbb'
    # r1, s1 = (18729973679190817623118111313771828863663483513774837152408759700444959675380395484441782281088986325568028125572313, 20359314114894398883483580278464256322867251438942572866576324564009786523201552170100051340293096655180830624945318)
    # r2, s2 = (18729973679190817623118111313771828863663483513774837152408759700444959675380395484441782281088986325568028125572313, 33549408991998253599552853970526509375371474724984217940328017323799040205020694232660707492411777350321253243465321)
    # cv   = Curve.get_curve('secp384r1')  ## <<---------- IMPORTANT: canviar curva 
    # n = cv.order   # depen de la curva
    # assert(r1==r2)
    # r = r1

    # # Calculs
    # k = sp.mod_inverse(s2-s1, n) * (m2 - m1)%n
    # print(f"Número aleatorio encontrado: {k}")

    # # se puede hacer con s1, m1 o con s2, m2
    # d1 = (s1*k-m1)*sp.mod_inverse(r, n) %n
    # d2 = (s2*k-m2)*sp.mod_inverse(r, n) %n
    # assert(d2==d1)
    # d = d1
    # print(f"Llave privada encontrada (d): {(d)}") # hex(d)
    # print()

    ######
    # verificar firmes
    #####
    # canviar aqui
    # h = 5572218363369325710622755349080158642966138912594496268137619782031501993116570169733490485653610033368823165157382759353621377017869899053722083617134315051
    # m = to_bytes(h)
    # assert(h==int(m.hex(), 16))
    # cv = Curve.get_curve('secp521r1')
    # pub_key = ECPublicKey(Point(183746701883757124826755524715142517173684662596382931014900106779410231692051781676595944589173697763631191386590655544007103631661168945042439908049126628,
    #                     1601281877710170848847338512967691812903583180826685392300517340541208413570012609627603954169927449316111853622325474586718412581245331911174500642483080471,
    #                     cv))
    
    # #####canviar tuple_firm per num atenea + comentar do_sign
    # # sign = do_sign(message=m)
    # tuple_sign = (636209411702914270661152765691119681822202526214190888223313780804486620649417809538075073320536552396577393606651565148805816715408423177786550261549407061, 
    #               5665944802029951168612385975560511149978964867796618009229554554695039618868560857058585498994051253971070241725582009074416192241470619741064412300461145432) # read_ASN(sign.hex())
    # found_sign = list_to_asn1(tuple_sign)

    # is_valid = verify_ecdsa_signature(pub_key, m, found_sign)
    # print("Apartado d: ")
    # print(f"¿Firma válida? {is_valid}")
    # print()


    ##########################
    ##### Calcular n punts??##
    ##########################

    # q = 641

    # calculs
    # lim_inf = q+1-2*sqrt(q)
    # lim_sup = q+1+2*sqrt(q)
    # print(f"lim_inf: {lim_inf}; lim_sup: {lim_sup}")
    # print()


    ########################
    #### Calcular exponent privat de clau pública curta
    ################

    # e, n = (3, 451)

    # calculs
    # p, q = list(sp.factorint(n).keys())[0], list(sp.factorint(n).keys())[1]
    # phi_n=(p-1)*(q-1)
    # d = sp.mod_inverse(e, phi_n)
    # print(f"Exponente privado={d}")
    # print()

    
    #####################
    ## leer certificado##
    #####################
    # canviar fitxer
    cert = read_certificate("./certificat_examen.pem")

    # calculs
    # print(cert)
    print("Emisor del certificado:", cert.issuer)
    print("Sujetos del certificado:", cert.subject)
    # print("Número de serie del certificado:", cert.serial_number)
    # print("Fecha de emisión:", cert.not_valid_before_utc)
    # print("Fecha de expiración:", cert.not_valid_after_utc)
    # signature = cert.signature
    # print("Firma del certificado (en hexadecimal):")
    # print(signature.hex())
    # print(f"signature alg: {cert.signature_algorithm_oid}")
    # signature --> emissor
    # pub key --> subjecte
    print(f"Pub key alg: {cert.public_key_algorithm_oid}")
    print(f"Pub key: {cert.public_key()}")

    ## https://cryptography.io/en/latest/x509/reference/#cryptography.x509.oid.PublicKeyAlgorithmOID

    if isinstance(cert.public_key(), rsa.RSAPublicKey):
        # Obtener el módulo (n) y el exponente público (e)
        public_numbers = cert.public_key().public_numbers()
        n = public_numbers.n  # El módulo (n)
        e = public_numbers.e  # El exponente público (e)
        print(f"10 primeros digitos n (base 10): {str(n)[0:10]}")
        print(f"longitud n bin: {len(bin(n)[2:])}")
    elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
        # Obtener el punto público (x, y) en la curva
        public_numbers = cert.public_key().public_numbers()
        x = public_numbers.x
        y = public_numbers.y
        print(f"x: {x}")
        print(f"curve: {cert.public_key().curve}")



    #####################
    ## Validez bloque####
    #####################

    