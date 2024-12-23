# Sergi GR
import os
import sympy as sp
from ecpy.curves import Point, Curve
from ecpy.keys import ECPublicKey
from ecpy.ecdsa import ECDSA
import hashlib


def read_data(file_path='', m_path=""):
    """
    Read variables needed to perform ECC calculations: p, b, Gx, Gy, n, Qx, Qy, f1, f2, message
    """
    with open(file=file_path) as file:
        file.readline()
        # curve_name (p, a, b, G, n) (nombre curva estandar)
        curve_name = file.readline().strip().split(" ")[1]
        
        # Q = (Qx, Qy)
        Q = file.readline().strip().split(" ")[1]
        if Q[0:2] == '04':
            mid = 8*8+2
            Qx = int(Q[2:mid],16)
            Qy = int(Q[mid:],16)
        else:
            raise AssertionError("Q no empieza por 04")
        Q = (Qx, Qy)
        

        # firma (f1, f2)
        f = file.readline().strip().split(" ")[1]
        f = bytes.fromhex(f)
        
        
    sha256_hash = hashlib.sha256()

    with open(file=m_path, mode="rb") as file:
    #     # message
        m = file.read()
        sha256_hash.update(m)
        m = sha256_hash.hexdigest()
    
    return curve_name, Q, f, m


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
    for n, k in possible_orders.items():
        if P*n == P.infinity():
            return n

# Generar una clave privada y calcular la pública
def generate_pubkey(Q):
    public_key = ECPublicKey(Q)
    return public_key


# Verificar una firma ECDSA
def verify_ecdsa_signature(public_key, message, signature):
    ecdsa = ECDSA()
    return ecdsa.verify(message, signature, public_key)

def calcula_preambulo():
    preambulo = "20"*64
    s = "TLS 1.3, server CertificateVerify"
    for c in s:
        preambulo += hex(ord(c))[2:]
    preambulo+="00"
    return preambulo


if __name__=="__main__":
    """
    TODO:
        - Preguntes: ordre del punt si ordre curva primer (q) n = 1, q?
        -
    """
    # Leemos los datos sacados manualmente de Wireshark
    curve_name, (Qx, Qy), f, m = read_data(file_path="./DATA.txt", m_path="./m.bin")
    
    # calculamos el preámbulo del mensaje firmado 
    preambulo = calcula_preambulo()

    # hacemos el hash externo
    sha256_hash = hashlib.sha256()
    message_bytes = bytes.fromhex(preambulo+m)
    sha256_hash.update(message_bytes)
    message = sha256_hash.hexdigest()

    message = bytes.fromhex(message)

    # Inicializamos la curva
    curve = Curve.get_curve(curve_name)
    G = curve.generator
    # Calculamos el orden de la curva
    generator_order = curve_order(curve=curve)

    # Respuestas a las preguntas:
    print()
    print("Apartado a:")
    print(f"Orden del generador: {generator_order}")
    print(f"Es el orden primo?: {sp.isprime(generator_order)}")
    print()

    # Point
    P = Point(Qx, Qy, curve, check=False)  
    # si check=True (default) lanza excepción si el punto no está en la curva

    # Generar clave pública
    public_key = generate_pubkey(Q=P)


    # Verificar si el punto público está en la curva
    print(f"Apartado b: ")
    print(f"La clave pública está en la curva?: {is_on_curve(curve, P)}")
    print()

    # Mirar orden del punto
    print("Apartado c: ")
    print(f"Orden del punto de la clave pública: {point_order(P, curve)}")
    print()

    
    # Verificar la firma
    is_valid = verify_ecdsa_signature(public_key, message, f)
    print("Apartado d: ")
    print(f"¿Firma válida? {is_valid}")
    print()
