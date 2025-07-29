import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.primitives import hashes

# Directories to create
directories = [
    "ca",
    "certs/user_certs",
    "keys/user_keys",
    "static",
    "utils"
]

# Create directories
for directory in directories:
    os.makedirs(directory, exist_ok=True)

# Generate CA key
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_key_path = "ca/ca_key.pem"
with open(ca_key_path, "wb") as f:
    f.write(ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Generate CA cert
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"NP"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Kathmandu"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Kathmandu"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SafeShare CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"SafeShare Root CA"),
])
ca_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
    ca_key.public_key()).serial_number(
    x509.random_serial_number()).not_valid_before(
    datetime.datetime.utcnow()).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(ca_key, hashes.SHA256())

ca_cert_path = "ca/ca_cert.pem"
with open(ca_cert_path, "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

# Create empty static/script.js file
with open("static/script.js", "w") as f:
    f.write("// JS will go here")

# Create utils/crypto_utils.py with placeholder
crypto_utils_code = '''import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CA_CERT_PATH = "ca/ca_cert.pem"
CA_KEY_PATH = "ca/ca_key.pem"

def generate_user_keys(username):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = f"keys/user_keys/{username}_private_key.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    return key, key_path

def issue_certificate(username, full_name, key):
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SafeShare Inc."),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_key, hashes.SHA256())

    cert_path = f"certs/user_certs/{username}_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    return cert_path
'''

with open("utils/crypto_utils.py", "w") as f:
    f.write(crypto_utils_code)

print("✅ All necessary directories and files created successfully.")
