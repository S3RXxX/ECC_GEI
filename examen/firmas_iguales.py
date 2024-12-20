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
    # m1 = 0x1d590294e8f7ccd77b893f543dbf79f7ab56ed15a8827593946650eaf3f893fe98caa6ecc0ecd8d509edc661cde4212a12c54057336d3148fb92fb6a442db1caf21 # b'aaa'
    # m2 = 0x7fc2d47786d0ea4b046fcff7acd4064806c1b7309ed88aed22c0e311741ef5e59343ba174a4dc2916ae70b4ea9412b5307a36d5db318316120f39def4678a9456 # b'bbb'
    # r1, s1 = (5836055730022888385227945117213377036940030910950650245331648175408505335892785431630373960724076887389464003569286803542872017318154533264318102031856806220, 3961636942176397609835502363706051226890097264031043370072541619740890963286300285110521436737934085725109430883404092482189038815855912130629815079886414520)
    # r2, s2 = (5836055730022888385227945117213377036940030910950650245331648175408505335892785431630373960724076887389464003569286803542872017318154533264318102031856806220, 6399224473896931302046449190617732041834256999915115853639641146632492968405878736944100968870890706314135416949700251430739345286170371064415270882896914150)
    # cv   = Curve.get_curve('secp521r1')  ## <<---------- IMPORTANT: canviar curva 
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
    ### canviar aqui
    h = 5054798442117127591724500032688361029006070602597001631666202630292382564415707378960510534884166224269106954339207077818729994100496690205852792396337683954
    m = to_bytes(h)
    assert(h==int(m.hex(), 16))
    cv = Curve.get_curve('secp521r1')
    pub_key = ECPublicKey(Point(872785165136472705968437467895851062511064516865924639595272527595480301456408650457524379208957144312020798606241143089663074020805825427104406241405322906,
                        1701451270116869270874888201059032734503264666233163051504686840869174045725134430208919347287400364969304679845684879132508500999601313620354175169642509545,
                        cv))
    
    #####canviar tuple_firm per num atenea + comentar do_sign
    # sign = do_sign(message=m)
    tuple_sign = (2903424952217878237524098877101657423040767416959818316814340075822596425230064693695252671042454485404708119162437884591535043921689597199870569720030099537, 
                  6495630910300361854348151792532757485438594435311888321302144374497884854714891171210532359705924695526015056553103718534044499748132805426129516994983057385) # read_ASN(sign.hex())
    found_sign = list_to_asn1(tuple_sign)

    found_tuple = read_ASN(found_sign.hex())
    print(tuple_sign==found_tuple)
    is_valid = verify_ecdsa_signature(pub_key, m, found_sign)
    print(f"¿Firma válida? {is_valid}")
    print()


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
    # cert = read_certificate("./certificat_examen.pem")

    # # calculs
    # # print(cert)
    # print("Emisor del certificado:", cert.issuer)
    # print("Sujetos del certificado:", cert.subject)
    # # print("Número de serie del certificado:", cert.serial_number)
    # # print("Fecha de emisión:", cert.not_valid_before_utc)
    # # print("Fecha de expiración:", cert.not_valid_after_utc)
    # # signature = cert.signature
    # # print("Firma del certificado (en hexadecimal):")
    # # print(signature.hex())
    # # print(f"signature alg: {cert.signature_algorithm_oid}")
    # # signature --> emissor
    # # pub key --> subjecte
    # print(f"Pub key alg: {cert.public_key_algorithm_oid}")
    # print(f"Pub key: {cert.public_key()}")

    # ## https://cryptography.io/en/latest/x509/reference/#cryptography.x509.oid.PublicKeyAlgorithmOID

    # if isinstance(cert.public_key(), rsa.RSAPublicKey):
    #     # Obtener el módulo (n) y el exponente público (e)
    #     public_numbers = cert.public_key().public_numbers()
    #     n = public_numbers.n  # El módulo (n)
    #     e = public_numbers.e  # El exponente público (e)
    #     print(f"10 primeros digitos n (base 10): {str(n)[0:10]}")
    #     print(f"longitud n bin: {len(bin(n)[2:])}")
    # elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
    #     # Obtener el punto público (x, y) en la curva
    #     public_numbers = cert.public_key().public_numbers()
    #     x = public_numbers.x
    #     y = public_numbers.y
    #     print(f"x: {x}")
    #     print(f"curve: {cert.public_key().curve}")



    #####################
    ## Comprovar exponents privats####
    #####################
    # e, n = (65537, 6400156760894376699346769986049886356206462053033026559434806785982944252545936554263479336150599517352254110606997963275152538146590368642321199797556363)
    # print(f"len n: {len(bin(n)[2:])}")
    # ds = [0,0,0,0]
    # ds[0] = 4988189658166800453474501070926265377414080533089562270470207935400600033700323757127611553887315525272848918798975646896654861515888527772157848969602191
    # ds[1] = 720165690818335159848590683670252100980544856100082753743434267445925998750248668012383823922866333191180521811957128283199223912322213490590329630422833
    # ds[2] = 263011636468736824180964256095260218394368995169152285212376639875715694996979194779323648137499032302487956208905712035005392549680450394826798964714873
    # ds[3] = 1177319745167933495516217111245243983566720717031013222274491895016136302503518141245443999708233634079873087415008544531393055274963976586353860296130793
    # import random
    # # message=361246216419
    # messages = [random.randint(0, 2**500) for _ in range(10)]
    # for i in range(4):
    #     d=ds[i]
    #     b=1
    #     for message in messages:
        
    #         c = pow(message, e, n)
    #         m = pow(c, d, n)
    #         if m!=message:
    #             b=0
    #             # print(f"{i+1}; d: {d}")
    #         else:
    #             pass
    #         # aux = (e*d)%n
    #         # if aux==1:
    #         #     print(f"{i+1}; d: {d}")
    #         # else:
    #         #     print(f"aux: {aux}")
    #     print(f"i+1: {i+1}, b {b}")
    #     if b:
    #         print(f"{i+1}; d: {d}")

    #################
    ### DH
    #################
    # p = 2362025289775063140246670231987126346661733974951185223054373723648118639447
    # g=5
    # a=875528579083828183663732473599195958663314000317846942140493551792582515645
    # alpha = 788113958397101103457052693616868974228970637445246673846681560940765877201
    # beta = 882681715848681895214057086177407123850752483433231314224986107306089596379
    
    
    # orden = sp.factorint(p-1)
    # print(f"orden {orden}")
    
    # q = 1181012644887531570123335115993563173330866987475592611527186861824059319723
    # orden=1
    # orden=2
    # # orden=q
    # # orden=2*q
    # a=(a%orden)+1
    # print(a)
    # secreto = sp.Pow(beta, a, p)
    # # secreto = secreto%p
    # print(f"Secreto acordado: {secreto}")


    ################
    ##### firma RSA PSS
    ##################
    # f1 = 0x36f218258ca994a9a312fd4b3ef573a2b6518c517b07a383cb43631ddff42480c84085256069e477b41f2e31da26915e80559295580471447902527e8684f06832ec3bbe8a7fd083376523f8d5298f8b526458bad6fa47320ba5186b382ef3c4d7cd999b72c720704e4359352cc3ad1d08481bde1088eaf02b90873ca91fe0b3
    # f2 = 0x1330ad411dfdf4359d58cad1fcc007f5e8bd52ab4fbe60982f597341989a6f5a2c5b3f01ecf51046733dbc52bb2d1a72da55b613e193d40b08b6f2edfb682a5f72faf5b230c363d9f358368bc57c12abeccaed13fe81553c46ff9a44ce3d10504fcff7bdb2ab2ee8309890411fcfc6977c6984df8037c556cc6d017335ac11d9
    # e=65537
    # n1=0x5715beb1516fadf8d297286f5fb2911cbfe5bcd23c51e639cbd171925b5296776e87b1d5f8e9384b064e9844654054a8847a1cbe472f9b33d213e38ee1e0267aed38edc58cc8c84844ffa567966be3f8264674d4e013fa90a1bab85ca264be02a94ff9fbda6cd73e99c69dc23430b55f16e74ff1d5cded0e5605b8491479d16f
    # n2=0x8358a0627e44bf96d106857f97b5f35c1494092337ce5abc1d4ab125674f8d1400445df3c9b158c0f8ca0ac3792d3877b341e615e7a1e73efa53986e8b8d3881af05754a4bfe40ad6023bee442bd8cc0ff612d14580b47e19bcdb1f31325b7ee34445d7664b6f5ddb9d15e7eca7735e1c2ea68ba12110d70153fcf9b5112bc51
    # n3=0xb33e762d9ddc6e23945d61b3d5b24cec7be5af7d1c485af4a89c857b5871a61c4aadfb77fd3ebda0ca8972a7b746371f2a5b09131a9958de3585aa47227ea79b57302ae1b200f4edb9bbbc254fb9e0a410bb52228b9211c69fc0a203a2dab34b492d7865e1f1658ffcc660a20249f926770974edd4860c105ed0883c6d182d3514fb071cb2ebfcc90508be17b0dd1a81fba4d0c5b70d4b7776d73757026c640cd1c715fb50a814d46e256f2be11600d5d17b63276f254aa52418e8d48af3b4d3580305b1387843339f4b87f8c793b919edf4b86268fe3c6470fe51c539f0bb803076f6d7e02952cc6c79f80b86883094c6991b737fb13b2c9169a2ff4f60ff75

    # print("modules lengths")
    # print(f"n1 {len(bin(n1)[2:])}")
    # print(f"n2 {len(bin(n2)[2:])}")
    # print(f"n3 {len(bin(n3)[2:])}")

    # print("signs length")
    # print(f"f1 {len(bin(f1)[2:])}")
    # print(f"f1 {len(bin(f2)[2:])}")

    # print()
    # print("verificar firmes??")
    # print("modulo 1")
    # f11 = pow(f1, e, n1)
    
    # f12 = pow(f2, e, n1)
    # print("modulo 2")
    # f21 = pow(f1, e, n2)
    # f22 = pow(f2, e, n2)
    # print(hex(f22))
    # 1 si 1
    # 1 no 2
    # 2 no 1
    # 2 si 2

    #####
    ### secreto ECDH
    #### 
    # from ecdsa import ellipticcurve, curves

    # # Definir la curva secp256r1 (NIST P-256)
    # curve = curves.NIST256r

    # # Parámetros de la curva
    # p = curve.curve.p()  # Primo p
    # a = curve.curve.a()  # Coeficiente a
    # b = curve.curve.b()  # Coeficiente b
    # G = curve.generator  # Generador G
    # n = curve.order      # Orden del generador

    # # Datos del problema
    # a_user = 99757649475609234237549415485681152677324456982430545871246393575012470071809  # Clave privada de A

    # # Coordenadas de puntos PA y PB
    # PA_x = 87744816607305399275442674944533123176226781977937210870891457432366761376438
    # PA_y = 13417419862466398674231535476050331259653271279219391166652643517585218042006
    # PB_x = 30511547628871852199886669234658121462032186156868575823831141832176599888358
    # PB_y = 46509648060412632523158189782645734212057407169551913275990748702272520465220

    # # Crear los puntos PA y PB en la curva
    # PA = ellipticcurve.Point(curve.curve, PA_x, PA_y, n)
    # PB = ellipticcurve.Point(curve.curve, PB_x, PB_y, n)

    # # Calcular el secreto común (clave privada a * PB)
    # shared_secret = a_user * PB

    # # Extraer la coordenada x del punto secreto compartido
    # x_shared = shared_secret.x()

    # # Resultado
    # print(f"La componente x del punto secreto común es: {x_shared}")

