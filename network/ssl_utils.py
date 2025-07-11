"""
SSL certificate generation and mTLS setup
"""
import ssl
import logging
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime

class SSLManager:
    """Manages SSL certificates and contexts"""
    
    def __init__(self):
        self.cert_file = "cert.pem"
        self.key_file = "key.pem"
        self.ca_cert_file = "cacert.pem"
        self.ca_key_file = "cakey.pem"
    
    def generate_ca_certificate(self):
        """Generate CA certificate"""
        try:
            # Generate CA private key
            ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Create CA certificate
            ca_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Coinium Network"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Coinium CA"),
            ])
            
            ca_cert = x509.CertificateBuilder().subject_name(
                ca_name
            ).issuer_name(
                ca_name
            ).public_key(
                ca_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).sign(ca_key, hashes.SHA256(), default_backend())
            
            # Save CA certificate and key
            with open(self.ca_cert_file, "wb") as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            
            with open(self.ca_key_file, "wb") as f:
                f.write(ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            logging.info("Generated CA certificate")
            return True
            
        except Exception as e:
            logging.error(f"Failed to generate CA certificate: {e}")
            return False
    
    def generate_ssl_certificate(self, hostname="localhost"):
        """Generate SSL certificate signed by CA"""
        try:
            # Load CA certificate and key
            if not os.path.exists(self.ca_cert_file) or not os.path.exists(self.ca_key_file):
                self.generate_ca_certificate()
            
            with open(self.ca_cert_file, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            with open(self.ca_key_file, "rb") as f:
                ca_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            # Generate server private key
            server_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Create server certificate
            server_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Coinium Network"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            server_cert = x509.CertificateBuilder().subject_name(
                server_name
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                server_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                    x509.DNSName("localhost"),
                    x509.IPAddress(bytes([127, 0, 0, 1])),
                ]),
                critical=False,
            ).sign(ca_key, hashes.SHA256(), default_backend())
            
            # Save server certificate and key
            with open(self.cert_file, "wb") as f:
                f.write(server_cert.public_bytes(serialization.Encoding.PEM))
            
            with open(self.key_file, "wb") as f:
                f.write(server_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            logging.info(f"Generated SSL certificate for {hostname}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to generate SSL certificate: {e}")
            return False
    
    def create_ssl_context(self, server_side=False, require_mtls=False):
        """Create SSL context"""
        try:
            # Ensure certificates exist
            if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
                self.generate_ssl_certificate()
            
            context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH if not server_side else ssl.Purpose.CLIENT_AUTH
            )
            
            if server_side:
                context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
                if require_mtls:
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.load_verify_locations(self.ca_cert_file)
            else:
                context.load_verify_locations(self.ca_cert_file)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # For self-signed certificates
            
            return context
            
        except Exception as e:
            logging.error(f"Failed to create SSL context: {e}")
            return None
    
    def wrap_socket(self, sock, server_side=False, hostname=None):
        """Wrap socket with SSL"""
        try:
            context = self.create_ssl_context(server_side=server_side)
            if context:
                if server_side:
                    return context.wrap_socket(sock, server_side=True)
                else:
                    return context.wrap_socket(sock, server_hostname=hostname)
            return None
            
        except Exception as e:
            logging.error(f"Failed to wrap socket with SSL: {e}")
            return None
    
    def verify_certificate(self, cert_data):
        """Verify certificate against CA"""
        try:
            # Load CA certificate
            with open(self.ca_cert_file, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            # Load certificate to verify
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Verify certificate signature
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_oid._name
            )
            
            # Check validity period
            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return False
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to verify certificate: {e}")
            return False

# Global SSL manager instance
ssl_manager = SSLManager()
