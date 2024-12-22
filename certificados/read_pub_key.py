
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def read_certificate(filepath):
    with open(file=filepath, mode="rb") as cert_file:
        cert_data = cert_file.read()

    # Cargar el certificado X.509 desde los datos PEM
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert    

if __name__ == "__main__":

    cert = read_certificate("./www.fib.upc.edu.crt")

    # print("Emisor del certificado:", cert.issuer)
    # print("Sujetos del certificado:", cert.subject)

    if isinstance(cert.public_key(), rsa.RSAPublicKey):
        # Obtener el módulo (n) y el exponente público (e)
        public_numbers = cert.public_key().public_numbers()
        n = public_numbers.n  # El módulo (n)
        e = public_numbers.e  # El exponente público (e)
        print(f"n (base 10): {n}")
        print(f"longitud n bin: {len(bin(n)[2:])}")
        print(f"longitud de n (base 10): {len(str(n))}")
        print()
        print(f"e (base 10): {e}")
        # print(f"len e bits: {len(bin(e)[2:])}")
        # print(f"len e base 10: {len(str(e))}")
