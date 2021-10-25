from http.server import SimpleHTTPRequestHandler, HTTPServer
import socketserver
import argparse, sys

PORT = 5003

parser = argparse.ArgumentParser()
parser.add_argument('http_address')

args = parser.parse_args(sys.argv[1:])

def kill_servers(IPv4_addr):
    with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
        print("HTTP Shutdown Server at port", PORT)
        httpd.handle_request()
        httpd.server_close()
        print("Shutdown started.")


class RequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        print(self.path)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

if __name__ == '__main__':
    kill_servers(args.http_address)