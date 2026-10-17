from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(500)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"internal error (injected case-b mirror)")
    def log_message(self, *a):
        pass
HTTPServer(("127.0.0.1", 18099), H).serve_forever()
