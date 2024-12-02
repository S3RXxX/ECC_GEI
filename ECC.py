# Sergi GR
import os
import sympy as sp
from ecpy.curves import Point, Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
from hashlib import sha256

# Inicializa la curva elíptica
curve_name = "secp256k1"
curve = Curve.get_curve(curve_name)  # Usa una curva estándar

def read_input(file_path=''):
    """
    Read variables needed to perform ECC calculations: p, b, Gx, Gy, n, Qx, Qy, f1, f2, message
    """
    with open(file=file_path) as f:
        f.read()
        # p, b, G, n (curva estandar)
        # Qx
        # Qy
        # f1
        # f2
        # message



    
# Verificar si un punto pertenece a la curva
def is_on_curve(point):
    x, y = point
    return curve.is_on_curve(x, y)

# Calcular el orden de un punto
def point_order(point):
    P = Point(point[0], point[1], curve)
    order = 1
    while not P.is_infinite():
        P = P + Point(point[0], point[1], curve)
        order += 1
    return order


# Generar una clave privada y calcular la pública
def generate_keypair():
    private_key = Key.gen_private_key(curve_name)
    public_key = Key.get_public_key(private_key, curve_name)
    return private_key, public_key


# Verificar una firma ECDSA
def verify_ecdsa_signature(public_key, message, signature):
    ecdsa = ECDSA()
    hashed_message = int.from_bytes(sha256(message).digest(), byteorder='big')
    return ecdsa.verify(signature, hashed_message, public_key, curve)

def curve_order():
    generator_order = curve.order
    return generator_order

if __name__=="__main__":
    G = curve.generator
    generator_order = curve.order
    print(f"Generador de la curva: {G}")
    print(f"Orden del generador: {generator_order}")

    # Generar claves
    private_key, public_key = generate_keypair()
    print(f"Clave privada: {private_key}")
    print(f"Clave pública: {public_key}")

    # Verificar si el punto público está en la curva
    print(f"La clave pública está en la curva: {is_on_curve((public_key.Wx, public_key.Wy))}")

    # Crear y verificar una firma ECDSA
    message = b"Este es un mensaje de prueba"
    ecdsa = ECDSA()
    hashed_message = int.from_bytes(sha256(message).digest(), byteorder='big')
    signature = ecdsa.sign(hashed_message, private_key, curve)
    print(f"Firma: {signature}")

    # Verificar la firma
    is_valid = verify_ecdsa_signature(public_key, message, signature)
    print(f"¿Firma válida? {is_valid}")