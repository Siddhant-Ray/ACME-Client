"""Referenced a bit from https://github.com/diafygi/acme-tiny and https://github.com/mpdavis/python-jose, 
design implementations are different"""

import argparse 
import subprocess, json, os, sys 
import base64, binascii, time, hashlib, re
import copy, textwrap, logging
from datetime import datetime, timedelta, timezone

from httpchallenge_server import register_http_challenge

from requests.models import Response

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

try:
    import requests
except ImportError:
    print("error in importing requests, install with pip")
    sys.exit(2)  

from requests.adapters import HTTPAdapter  
from requests.packages.urllib3.util.retry import Retry

class ACMEClient():

    def __init__(self, directory, dns_server):
        
        self.directory = directory
        self.dns_server = dns_server

        # Required paramters in the JSON object in the ACME directory
        self.revokeCert_url = None
        self.newNonce_url = None
        self.newAccount_url = None
        self.newOrder_url = None

        self.account_orders = None
        self.account_kid = None

        self.key = None
        self.signing_alg = None

        self.client_session = requests.Session()
        self.jose_session = requests.Session()

        #retry = Retry(connect=3, backoff_factor=0.5)

        # ACME clients MUST send a User-Agent header field, in accordance with [RFC7231]
        self.client_session.headers.update({"User-Agent": "sidray-acme-project"})
        self.client_session.mount('https://', HTTPAdapter(max_retries=0))

        self.jose_session.headers.update(
            {"User-Agent": "sidray-acme-project", "Content-Type": "application/jose+json"})
        self.jose_session.mount('https://', HTTPAdapter(max_retries=0))

        self.generate_keypair()
        print("Client keypair generated")


    # Encode in B64 as per ACME RFC specification
    # https://stackoverflow.com/questions/23164058/how-to-encode-text-to-base64-in-python
    def encode_b64(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip("=")
    
    # Used the pycryptodome documentation 
    # https://pycryptodome.readthedocs.io/en/latest/src/public_key/#available-key-types

    """An ACME server MUST implement the "ES256" signature algorithm
        [RFC7518] and SHOULD implement the "EdDSA" signature algorithm using
        the "Ed25519" variant (indicated by "crv") [RFC8037]."""

    def generate_keypair(self):

        self.key = ECC.generate(curve="p256")

        '''f = open("private_key.pem", "wt")
        f.write(self.key.export_key(format='PEM'))
        f.close()'''

        self.signing_alg = DSS.new(self.key, "fips-186-3")

    # Get the values from the root ACME directory
    def get_directory(self):

        
        directory_request = self.client_session.get(self.directory)
    
        # Request code 200 for directory
        if directory_request.status_code == 200:
            jose_request_object = directory_request.json()

            self.revokeCert_url = jose_request_object["revokeCert"]
            self.newNonce_url = jose_request_object["newNonce"]
            self.newAccount_url = jose_request_object["newAccount"]
            self.newOrder_url = jose_request_object["newOrder"]
            return jose_request_object

        else:
            print("get_directory returned HTTP {} error. Response body: {}".format(
                directory_request.status_code, directory_request.json()))
            return False

    # Split x and y coordinates : https://openid.net/specs/draft-jones-json-web-signature-04.html#DefiningECDSA
    # https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html#Crypto.PublicKey.ECC.EccPoint
    def export_jwk(self):
        jwk_object = {
            "crv": "P-256",
            "kid": "1",
            "kty": "EC",
            "x": self.encode_b64(self.key.pointQ.x.to_bytes()),
            "y": self.encode_b64(self.key.pointQ.y.to_bytes()),
        }

        return jwk_object

    def get_nonce(self):
        if self.newNonce_url == None:
            print("get_nonce: URL unknown, directory for nonce is missing")
            return

        request = self.client_session.get(self.newNonce_url)

        # 204 for no content
        if request.status_code == 200 or request.status_code == 204:
            self.nextNonce = request.headers["Replay-Nonce"]
            print("Obtained next nonce, {}".format(self.nextNonce))
            return self.nextNonce
        else:
            print("get_nonce returned HTTP {} error. Response body: {}".format(
                request.status_code, request.json()))
            return None

    def create_key_authorization(self, token):
        key = {
            "crv": "P-256",
            "kty": "EC",
            "x": self.encode_b64(self.key.pointQ.x.to_bytes()),
            "y": self.encode_b64(self.key.pointQ.y.to_bytes()),
        }

        h = self.encode_b64(SHA256.new(str.encode(
            json.dumps(key, separators=(',', ':')), encoding="utf-8")).digest())
        key_auth = "{}.{}".format(token, h)

        return key_auth

    def create_account(self):
        payload = {
            "termsOfServiceAgreed": True,
        }

        jose_payload = self.create_jose_jwk(self.newAccount_url, payload)
        jose_request = self.jose_session.post(self.newAccount_url, json=jose_payload)

        # Request code 201 for account creation
        if jose_request.status_code == 201:
            jose_request_object = jose_request.json()


            ## TODO : account orders missing for now, need to investigate why not working 

            #self.account_orders = jose_request_object["orders"]
            self.account_kid = jose_request.headers["Location"]

            return jose_request_object
        else:
            print("create_account returned HTTP {} error. Response body: {}".format(
                jose_request.status_code, jose_request.json()))
            return False
    

    """The "jwk" and "kid" fields are mutually exclusive. Servers MUST
        reject requests that contain both."""
    
    """
    All the new_accounts and revoke requests must be signed with jwk
    """

    def create_jose_jwk(self, url, payload):

        protected = {
            "alg": "ES256",
            "jwk": self.export_jwk(),
            "nonce": self.get_nonce(),
            "url": url
        }

        encoded_header = self.encode_b64(json.dumps(protected))
        encoded_payload = self.encode_b64(json.dumps(payload))

        # Create SHA thumbprint
        h = SHA256.new(str.encode("{}.{}".format(
            encoded_header, encoded_payload), encoding="ascii"))

        signature = self.signing_alg.sign(h)

        jose_object = {
            "protected": encoded_header,
            "payload": encoded_payload,
            "signature": self.encode_b64(signature)
        }

        return jose_object


    """
    All other requests must be signed with the KID
    """

    def create_jose_kid(self, url, payload):

        if not self.account_kid:
            print("No account kid found")
            return None

        protected = {
            "alg": "ES256",
            "kid": self.account_kid,
            "nonce": self.get_nonce(),
            "url": url
        }

        encoded_header = self.encode_b64(json.dumps(protected))

        # Create SHA thumbprint
        if payload == "":
            encoded_payload = ""
            h = SHA256.new(str.encode(
                "{}.".format(encoded_header), encoding="ascii"))
        else:
            encoded_payload = self.encode_b64(json.dumps(payload))
            h = SHA256.new(str.encode("{}.{}".format(
                encoded_header, encoded_payload), encoding="ascii"))
        signature = self.signing_alg.sign(h)

        kid_jose_object = {
            "protected": encoded_header,
            "payload": encoded_payload,
            "signature": self.encode_b64(signature)
        }

        return kid_jose_object

    # https://github.com/diafygi/acme-tiny/blob/master/acme_tiny.py
    def poll_resource_status(self, order_url, success_states, failure_states):
        while True:
            payload = ""
            jose_payload = self.create_jose_kid(order_url, payload)
            jose_request = self.jose_session.post(order_url, payload, json=jose_payload)
            jose_request_object = jose_request.json()

            if jose_request.status_code == 200:
                if jose_request_object["status"] in success_states:
                    print("Resource {} has {} state".format(
                        order_url, jose_request_object["status"]))
                    return jose_request_object
                elif jose_request_object["status"] in failure_states:
                    print("Resource {} has {} state, treated as failure".format(
                        order_url, jose_request_object["status"]))
                    return False
            else:
                print("polling resource returned HTTP {} error. Response body: {}".format(
                    jose_request.status_code, jose_request.json()))

            time.sleep(1)

    def issue_certificate(self, domains, begin=datetime.now(timezone.utc), duration=timedelta(days=365)):
        payload = {
            "identifiers": [{"type": "dns", "value": domain} for domain in domains],
            "notBefore": begin.isoformat(),
            "notAfter": (begin + duration).isoformat()
        }

        jose_payload = self.create_jose_kid(self.newOrder_url, payload)
        response = self.jose_session.post(self.newOrder_url, json=jose_payload)

        if response.status_code == 201:
            jose_request_object = response.json()

            return jose_request_object, response.headers["Location"]
        else:
            print("certificate issue request has returned HTTP {} error. Response body: {}".format(
                response.status_code, response.json()))
            return False, False

    def authorize_certificate(self, auth_url, auth_scheme):
        payload = ""

        jose_payload = self.create_jose_kid(auth_url, payload)

        request = self.jose_session.post(auth_url, json=jose_payload)

        if request.status_code == 200:
            jose_request_object = request.json()

            for challenge in jose_request_object["challenges"]:
                key_auth = self.create_key_authorization(challenge["token"])

                if auth_scheme == "dns01" and challenge["type"] == "dns-01":
                    key_auth = self.encode_b64(SHA256.new(
                        str.encode(key_auth, encoding="ascii")).digest())

                    self.dns_server.zone_add_TXT(
                        "_acme-challenge.{}".format(jose_request_object["identifier"]["value"]), key_auth)
                    return challenge

                elif auth_scheme == "http01" and challenge["type"] == "http-01":
                    register_http_challenge(challenge["token"], key_auth)
                    return challenge

            print("Valid challenge not found for scheme {} in ACME server response: {}".format(
                auth_scheme, jose_request_object["challenges"]))
            return False

        else:
            print("challenge failed and returned HTTP {} error. Response body: {}".format(
                request.status_code, request.json()))
            return False

    def validate_certificate(self, validate_url):
        payload = {}
        jose_payload = self.create_jose_kid(validate_url, payload)
        response = self.jose_session.post(validate_url, json=jose_payload)

        if response.status_code == 200:
            jose_request_object = response.json()

            return jose_request_object
        else:
            print("validating certificate failed,  returned HTTP {} error. Response body: {}".format(
                response.status_code, response.json()))
            return False

    # For finalising the certificate, wait till it is valid
    def finalize_certificate(self, order_url, finalize_url, der):
        jose_request_object = self.poll_resource_status(
            order_url, ["ready", "processing", "valid"], ["invalid"])

        if not jose_request_object:
            return False

        payload = {
            "csr": self.encode_b64(der)
        }

        jose_payload = self.create_jose_kid(finalize_url, payload)
        response = self.jose_session.post(finalize_url, json=jose_payload)

        if response.status_code == 200:
            jose_request_object = self.poll_resource_status(
                order_url, ["valid"], ["ready", "invalid", "pending"])
            if jose_request_object:
                return jose_request_object["certificate"]
            else:
                return False
        else:
            print("finalize certificate request failed, returned HTTP {} error. Response body: {}".format(
                response.status_code, response.json()))
            return False

    def download_certificate(self, cert_url):
        payload = ""
        jose_payload = self.create_jose_kid(cert_url, payload)

        response = self.jose_session.post(cert_url, json=jose_payload)
        if response.status_code == 200:
            return response.content

        else:
            print("downloading certifcate failed, returned HTTP {} error. Response body: {}".format(
                response.status_code, response.json()))
            return False

    def revoke_certificate(self, cert):
        payload = {
            "certificate": self.encode_b64(cert)
        }
        jose_payload = self.create_jose_kid(self.revokeCert_url, payload)

        response = self.jose_session.post(self.revokeCert_url, json=jose_payload)
        if response.status_code == 200:
            return response.content

        else:
            print("revoking certificate failed, returned HTTP {} error. Response body: {}".format(
                response.status_code, response.json()))
            return False



