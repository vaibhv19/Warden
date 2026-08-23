import http.server
import socketserver
import time
import urllib.parse

PORT = 8000


class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # 1. Homepage index
        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html = """
            <html>
            <head><title>Vulnerable Test Target</title></head>
            <body>
                <h1>Warden Test Target</h1>
                <p>Welcome to the authorized vulnerable target environment.</p>
                <ul>
                    <li><a href="/search?q=test">Search endpoint (XSS)</a></li>
                    <li><a href="/users?id=1">User Profile endpoint (SQLi)</a></li>
                    <li><a href="/admin">Admin Console (Auth Bypass)</a></li>
                    <li><a href="/secure">Secure Endpoint (Auth Check)</a></li>
                </ul>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
            return

        # 2. XSS Search endpoint
        elif path == "/search":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            q = query_params.get("q", [""])[0]
            # Reflect q unescaped for XSS validation
            response = f"""
            <html>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: {q}</p>
            </body>
            </html>
            """
            self.wfile.write(response.encode("utf-8"))
            return

        # 3. SQLi User endpoint
        elif path == "/users":
            user_id = query_params.get("id", [""])[0]
            # Time-based SQLi simulated trigger
            if "sleep" in user_id.lower() or "time" in user_id.lower():
                time.sleep(5)
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"User Profile (delayed)")
                return

            # Error-based SQLi simulated trigger
            if "'" in user_id or '"' in user_id:
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(
                    b'Internal Server Error: sqlite3.OperationalError: near "\'": syntax error'
                )
                return

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(f"User Profile for ID: {user_id}".encode("utf-8"))
            return

        # 4. Vulnerable Admin console (Auth bypass)
        elif path == "/admin":
            # Vulnerability: ignores auth headers and permits access
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Admin Console</h1><p>Sensitive operations page.</p>")
            return

        # 5. Secure endpoint (no false positives)
        elif path == "/secure":
            auth_header = self.headers.get("Authorization", "")
            if auth_header == "Bearer secret-admin-token":
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Secure Admin Data")
                return
            else:
                self.send_response(401)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"401 Unauthorized: missing or invalid token")
                return

        # 6. Fallback 404
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")


def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
        print(f"Serving vulnerable test target on port {PORT}...")
        httpd.serve_forever()


if __name__ == "__main__":
    run_server()
