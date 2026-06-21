#!/usr/bin/env python3
"""
Tiny static server for the VulnIQ dashboard that sends no-cache headers.

Use this instead of `python3 -m http.server` so the browser always fetches the
latest dashboard.html / JS. Plain http.server lets the browser cache the page,
which is how you can end up staring at an *old* build whose tabs don't refresh
after an upload even though the code on disk is correct.

    python3 frontend/serve.py        # serves the frontend dir on :5500
    python3 frontend/serve.py 5600   # custom port

It always serves the directory this script lives in, regardless of where you
run it from, so the path is stable whether you launch it from the project root
or from inside frontend/.
"""
import functools
import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler

HERE = os.path.dirname(os.path.abspath(__file__))


class NoCacheHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5500
    handler = functools.partial(NoCacheHandler, directory=HERE)
    print(f"VulnIQ dashboard (no-cache) → http://localhost:{port}/dashboard.html")
    HTTPServer(("", port), handler).serve_forever()
