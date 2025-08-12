import datetime
from OpenSSL import crypto
import os
from time import time


#create rsa key pair
def gen_privkey():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bits=4096)
    return key

#create x509 req object
def create_csr(key):
    csr = crypto.X509Req()
    csr.get_subject().commonName = "CommonName"
    csr.get_subject().stateOrProvinceName = "State"
    csr.get_subject().localityName = "Local"
    csr.get_subject().organizationName = "Organization"
    csr.get_subject().organizationalUnitName = "Unit"
    csr.get_subject().emailAddress = "user@host.com"
    csr.get_subject().countryName = "US"
    csr.set_pubkey(key)
    csr.sign(key, "sha256")
    return csr

def create_cert(csr, key):
    cert = crypto.X509()
    cert.get_subject().commonName = csr.get_subject().commonName
    cert.get_subject().stateOrProvinceName = csr.get_subject().stateOrProvinceName
    cert.get_subject().localityName = csr.get_subject().localityName
    cert.get_subject().organizationName = csr.get_subject().organizationName
    cert.get_subject().organizationalUnitName = csr.get_subject().organizationalUnitName
    cert.get_subject().emailAddress = csr.get_subject().emailAddress
    cert.get_subject().countryName = csr.get_subject().countryName
    curr_year = datetime.date.today().year
    next_year = curr_year + 1
    cert.set_notBefore("{}0101000000Z".format(curr_year).encode())
    cert.set_notAfter("{}0101000000Z".format(next_year).encode())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    return cert

def write_certfile(key_name: str="ca.key", csr_name: str="ca.csr", cert_name: str="ca.cert", dir_name: str="certs") -> dict:
    key = gen_privkey()
    csr = create_csr(key)
    cert = create_cert(csr, key)
    dirname = os.path.join(os.getcwd(), dir_name)
    if not os.path.exists(dirname):
        os.mkdir(dirname)
    key_path = os.path.join(dirname, key_name)
    csr_path = os.path.join(dirname, csr_name)
    cert_path = os.path.join(dirname, cert_name)

    with open(key_path, "wb") as fh:
        fh.write(crypto.dump_privatekey(crypto.FILETYPE_TEXT, key))
    
    with open(csr_path, "wb") as fh:
        fh.write(crypto.dump_certificate_request(crypto.FILETYPE_TEXT, csr))
    
    with open(cert_path, "wb") as fh:
        fh.write(crypto.dump_certificate(crypto.FILETYPE_TEXT, cert))

    return {
        "key": key_path,
        "csr": csr_path,
        "cert": cert_path
    }