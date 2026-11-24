"""Tiny canary listener. Any request is logged; GET /_hits returns the log; POST /_reset clears it."""
import json, time
from http.server import BaseHTTPRequestHandler, HTTPServer
HITS = []
class H(BaseHTTPRequestHandler):
    def _handle(self):
        if self.path == "/_hits":
            body = json.dumps(HITS).encode()
        elif self.path == "/_reset":
            HITS.clear(); body = b"ok"
        else:
            HITS.append({"path": self.path, "method": self.command, "ts": time.time(),
                         "from": self.client_address[0]})
            body = b"canary"
        self.send_response(200); self.end_headers(); self.wfile.write(body)
    do_GET = do_POST = do_PUT = do_HEAD = _handle
    def log_message(self, *a): pass
HTTPServer(("0.0.0.0", 9999), H).serve_forever()
