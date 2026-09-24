"""Run the local incident workspace: python app/workspace_server.py."""
from __future__ import annotations
import argparse
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8768)
    parser.add_argument('--project-root', type=Path, default=ROOT)
    args = parser.parse_args()
    sys.path.insert(0, str(args.project_root / 'src'))
    from workspace_service import Workspace, SnapshotChanged
    service = Workspace()
    token = secrets.token_urlsafe(32)
    static = Path(__file__).parent / 'static'

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # Questions, records and credentials are never written to access logs.
            pass

        def send(self, value, status=200, mime='application/json; charset=utf-8', extra=None):
            body = json.dumps(value, ensure_ascii=False).encode() if mime.startswith('application/json') else value
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def allowed_host(self):
            return self.headers.get('Host') in (f'127.0.0.1:{args.port}', f'localhost:{args.port}')

        def do_GET(self):
            if not self.allowed_host():
                return self.send({'error': 'Invalid host'}, 403)
            route = self.path.split('?', 1)[0]
            try:
                if route == '/api/workspace':
                    return self.send({**service.snapshot(), 'request_token': token})
                if route == '/api/brief':
                    revision = parse_qs(urlsplit(self.path).query).get('revision', [''])[0]
                    return self.send(service.brief(revision).encode(), mime='text/plain; charset=utf-8', extra={'Content-Disposition': 'attachment; filename="incident-brief.txt"'})
                names = {'/': ('index.html', 'text/html'), '/workspace.js': ('workspace.js', 'text/javascript'), '/workspace.css': ('workspace.css', 'text/css')}
                if route in names:
                    name, mime = names[route]
                    return self.send((static / name).read_bytes(), mime=mime + '; charset=utf-8')
                return self.send({'error': 'Not found'}, 404)
            except (SnapshotChanged, ValueError, OSError):
                return self.send({'error': 'Investigation files are unavailable or changing. Wait for the build to finish and retry.'}, 503)

        def do_POST(self):
            if not self.allowed_host() or self.headers.get('X-Workspace-Token') != token:
                return self.send({'error': 'Refresh the workspace and try again.'}, 403)
            origin = self.headers.get('Origin')
            if origin and origin not in (f'http://127.0.0.1:{args.port}', f'http://localhost:{args.port}'):
                return self.send({'error': 'Origin not allowed'}, 403)
            if self.path != '/api/ask':
                return self.send({'error': 'Not found'}, 404)
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 24000:
                    return self.send({'error': 'Question is too large.'}, 413)
                payload = json.loads(self.rfile.read(length))
                question = payload.get('question', '')
                history = payload.get('history', [])
                if not isinstance(question, str) or not 1 <= len(question.strip()) <= 4000 or not isinstance(history, list):
                    return self.send({'error': 'Enter a question of up to 4,000 characters.'}, 400)
                return self.send(service.ask(question.strip(), payload.get('revision'), history))
            except (ValueError, TypeError, AttributeError):
                return self.send({'error': 'Invalid request.'}, 400)
            except SnapshotChanged:
                return self.send({'error': 'The investigation is rebuilding. Refresh after it finishes.'}, 409)
            except Exception:
                return self.send({'error': 'The answer service could not finish. Please retry; the investigation pages remain available.'}, 503)

    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print(f'Incident workspace: http://127.0.0.1:{args.port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
