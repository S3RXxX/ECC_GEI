
if __name__=="__main__":
    pass

    """
    C: Count nº revoked certificates:
        -cmd: openssl crl -in .\GEANTOVRSACA4.crl -text -noout | grep 'Serial Number:' | wc -l
        -Result: 22307
    """