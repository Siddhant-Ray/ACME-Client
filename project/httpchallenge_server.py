from http.server import SimpleHTTPRequestHandler, HTTPServer
import socketserver
import sys, argparse

PORT = 5002

parser = argparse.ArgumentParser()
parser.add_argument('keyAuth')
parser.add_argument('http_address')

args = parser.parse_args(sys.argv[1:])

keyAuth_list_addition = args.keyAuth.split('+')
keyAs = []
for key in keyAuth_list_addition:
    if not key:
        keyAs.append(key)

print(keyAs)

class RequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):

        self.protocol_version = "HTTP/1.1"
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()

        for single_key in keyAs:
            kAuth = single_key
            token = single_key.split('.')[0]
            print(kAuth)
            if self.path == ('/.well-known/acme-challenge/'+token):
                self.wfile.write(bytes(kAuth, "utf8"))

            
httpd = HTTPServer((args.http_address, PORT), RequestHandler)
httpd.serve_forever()