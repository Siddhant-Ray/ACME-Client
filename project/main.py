import os
import sys
import threading
import time
from pathlib import Path
import argparse

import flask

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acme_client import ACMEClient
from dns_server import newDNSServer
from https_server import start_https_server
from httpchallenge_server import start_http_challenge_server

httpshutdown_server = flask.Flask(__name__)

def kill_all_processes():
    os._exit(0)

@httpshutdown_server.route('/shutdown')
def route_shutdown():
    print("Shutting down...")

    # https://stackoverflow.com/questions/15562446/how-to-stop-flask-application-without-using-ctrl-c

    func = flask.request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

    return "Server shutting down"

# https://www.programcreek.com/python/?CodeExample=generate+csr
def generate_csr_key(domains):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "ZH"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "sidray-acme-project"),
        x509.NameAttribute(NameOID.COMMON_NAME, "sidray-acme-project"),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)
                                     for domain in domains]),
        critical=False,
    ).sign(key, hashes.SHA256())

    der = csr.public_bytes(serialization.Encoding.DER)

    return key, csr, der


key_path = Path(__file__).parent.absolute()/ "key.pem"
cert_path = Path(__file__).parent.absolute()/ "cert.pem"

# write the cert and the pem file for the key  
def write_certificates(key, cert):
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(cert)


def obtain_certificate(args):
    dns = newDNSServer()
    start_http_challenge_server()

    for domain in args.domain:
        dns.zone_add_A(domain, args.record)

    dns.server_start()
    print("[Get certificate] DNS server started")

    acme = ACMEClient(args.dir, dns)
    if not acme:
        print("Create client Error. Process killed.")
        return False, False

    directory = acme.get_directory()
    if not directory:
        print("Get directory Error. Process killed.")
        return False, False

    print("[Get directory]", directory)

    account = acme.create_account()
    if not account:
        print("Create account error. Process killed.")
        return False, False

    print("[Create account]", account)

    cert_order, order_url = acme.issue_certificate(args.domain)

    if not cert_order:
        print("Certificate order error. Process killed.")
        return False, False

    print("[Cert order]", cert_order)

    validate_urls = []
    finalize_url = cert_order["finalize"]

    for auth in cert_order["authorizations"]:
        cert_auth = acme.authorize_certificate(auth, args.challenge)

        if not cert_auth:
            print("Certificate authentication error. Process killed")
            return False, False
        validate_urls.append(cert_auth["url"])

        print("[Cert auth]", cert_auth)

    for url in validate_urls:
        cert_valid = acme.validate_certificate(url)

        if not cert_valid:
            print("Certificate validation error. Process killed")
            return False, False

        print("[Cert valid]", cert_valid)

    key, csr, der = generate_csr_key(args.domain)

    cert_url = acme.finalize_certificate(order_url, finalize_url, der)
    if not cert_url:
        print("[Certificate finalizing error. Process killed")
        return False, False

    print("[Cert finalize]", cert_url)

    cert = acme.download_certificate(cert_url)

    if not cert:
        print("Certificate downloading error. Process killed.")
        return False, False

    print("[Cert download]", cert)

    write_certificates(key, cert)

    crypto_cert = x509.load_pem_x509_certificate(cert)

    if args.revoke:
        acme.revoke_certificate(crypto_cert.public_bytes(serialization.Encoding.DER))

    return key, cert


def start_server_to_use_cert(args):
    # Get certificate, however I will read the certificate from the stored file 
    key, cert = obtain_certificate(args)

    if not key:
        print("No key found, not starting the https server, killing all..")
        kill_all_processes()

    # Start HTTPS server
    start_https_server(key_path, cert_path)

# Controller (still used to my SDN terminology haha) to initiate the certificate process, and start the https server at the end
def controller(args):
    controller_thread = threading.Thread(target=lambda: httpshutdown_server.run(
        host="0.0.0.0", port=5003, debug=False, threaded=True))
    controller_thread.start()

    https_server_thread = threading.Thread(target=lambda: start_server_to_use_cert(args))
    https_server_thread.start()

    # Kill application when the controller terminates
    controller_thread.join()
    kill_all_processes()

def main():
    parser = argparse.ArgumentParser(description="sidray-acme-project wrapper")
    parser.add_argument("--dir", help="the directory URL of the ACME server that should be used", required=True)
    parser.add_argument("challenge", choices=["dns01", "http01"])
    parser.add_argument("--record", required=True, help="the IPv4 address which must be returned by your DNS server for all A-record queries")
    parser.add_argument("--domain", action="append", help="the domain for  which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net")
    parser.add_argument("--revoke", action="store_true", help="Immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.")

    args = parser.parse_args()

    print("Parsed arguments: ", args)

    controller(args)

if __name__ == "__main__":
    main()