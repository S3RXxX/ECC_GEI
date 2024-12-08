# Sergi GR
import os
import sympy as sp
from ecpy.curves import Point, Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
from hashlib import sha256


def read_input(file_path=''):
    """
    Read variables needed to perform ECC calculations: p, b, Gx, Gy, n, Qx, Qy, f1, f2, message
    """
    with open(file=file_path) as f:
        f.read()
        # p, a, b, G, n (nombre curva estandar)
        
        # Qx
        # Qy

        # f1
        # f2

        # message


# Devuelve el número (orden) de puntos de la curva
def curve_order(curve):
    generator_order = curve.order
    return generator_order

# Verificar si un punto pertenece a la curva
def is_on_curve(curve, point):
    return curve.is_on_curve(point)

# Calcular el orden de un punto
def point_order(point, curve):
    """El orden de un punto es un divisor del número de puntos de la curva"""
    c = curve_order(curve)
    
    possible_orders = sp.factorint(c)
    # print(possible_orders)

    P = point
    print(P)
    print(P.infinity())

    for n, k in possible_orders.items():
        if P*n == P.infinity():
            return n

# Generar una clave privada y calcular la pública
def generate_keypair(curve,Q, d):
    public_key = ECPublicKey(Q)
    private_key = ECPrivateKey(d, curve)
    return private_key, public_key


# Verificar una firma ECDSA
def verify_ecdsa_signature(public_key, message, signature):
    ecdsa = ECDSA()
    # hashed_message = int.from_bytes(sha256(message).digest(), byteorder='big')
    return ecdsa.verify(message, signature, public_key)



if __name__=="__main__":
    """
    TODO:
        -https://pypi.org/project/ECPy/
        -
    """
    # Inicializa la curva elíptica (substituir pel de Wireshark)
    curve_name = "secp256k1"
    curve = Curve.get_curve(curve_name)  # Canviar per la que toqui
    
    G = curve.generator
    generator_order = curve_order(curve=curve)
    # print(f"Generador de la curva: {G}")
    print()
    print("Apartado a:")
    print(f"Orden del generador: {generator_order}")
    print(f"Es el orden primo?: {sp.isprime(generator_order)}")
    print()

    # Point (substituir pel llegit a Wireshark)
    P = Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
                       0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
                       curve, check=False)  
    # si check=True (default) lanza excepción si el punto no está en la curva

    # Generar claves (borrar clau privada)
    d = 0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5
    private_key, public_key = generate_keypair(curve=curve, Q=P, d=d)
    # print(f"Clave privada: {private_key}")
    # print(f"Clave pública: {public_key}")
    # print()

    # Verificar si el punto público está en la curva
    print(f"Apartado b: ")
    print(f"La clave pública está en la curva?: {is_on_curve(curve, P)}")
    print()

    print("Apartado c: (NOOOOOOOOOOOOOOOOOOOO)")
    print(f"Orden del punto de la clave pública: {point_order(P, curve)}")
    print()

    # Crear y verificar una firma ECDSA (substituir per f1, f2 de Wireshark)
    # (borrar)
    message = b"Este es un mensaje de prueba"
    ecdsa = ECDSA()
    signature = ecdsa.sign(message, private_key, curve)
    # print(f"Firma: {signature}")
    # print()

    # Verificar la firma
    is_valid = verify_ecdsa_signature(public_key, message, signature)
    print("Apartado d: ")
    print(f"¿Firma válida? {is_valid}")
    print()
