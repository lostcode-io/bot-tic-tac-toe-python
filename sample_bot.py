"""
'Tic-tac-toe' game bot for the LostCode.io website.

This is sample bot, the simplest you can do: and will choose his turn absolutely random.
"""
import argparse
import http.server
import json
import os
import random
import socket
import sys
from urllib.parse import parse_qs, urlparse


class SampleBot(http.server.BaseHTTPRequestHandler):
    """Tic-tac-toe sample bot class."""

    version: str
    secret: str

    def __init__(self, version: str, secret: str, *args):
        self.version = version
        self.secret = secret
        super().__init__(*args)

    @property
    def server_version(self):
        return f"SampleTicTacToeBot/{self.version}"

    def get_response_message(self, code):
        """Get HTTP response name by code."""
        try:
            return self.responses[code][0]
        except KeyError:
            return 'Unknown'

    def send_response(self, code, message=None):
        """Add the response header to the headers buffer, log response code."""
        self.log_request(code)
        self.send_response_only(code, message)

    def send_empty_response(self):
        """Send empty '200 OK' response."""
        self.send_response(200, self.responses[200][0])
        self.send_header('Connection', "close")
        self.send_header('Content-Length', "0")
        self.end_headers()

    def send_json_response(self, data, code=200, message=None):
        """Send JSON response."""
        if message is None:
            message = self.get_response_message(code)

        data = {
            'status': "ok",
            'game': "tic-tac-toe",
            'version': self.version,
            'secret': self.secret,
            **data,
        }

        body = json.dumps(data).encode('UTF-8', 'replace')
        self.send_response(code, message)
        self.send_header('Content-Type', "application/json")
        self.send_header('Connection', "close")
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        """Send and log an error reply."""
        if message is None:
            message = self.get_response_message(code)

        self.log_error(f"Error {code}: {message}")
        response = {'error': explain or message}
        self.send_json_response(response, code, message)

    def do_status(self, _):
        """Process 'status' command.

        https://lostcode.io/docs/tic-tac-toe/api/status/
        """
        self.send_json_response({'message': "Hi, there!"})

    def do_start(self, _):
        """Process 'start' command.

        https://lostcode.io/docs/tic-tac-toe/api/start/
        """
        self.send_json_response({'accept': True, 'message': "Let's go!"})

    def do_turn(self, data):
        """Process 'turn' command.

        https://lostcode.io/docs/tic-tac-toe/api/turn/
        """
        if 'board' not in data:
            self.send_error(400, explain="No 'board' found in data")
            return

        moves_allowed = []
        for coord_x in range(0, 3):
            for coord_y in range(0, 3):
                if data['board'][coord_x][coord_y] == 0:
                    moves_allowed.append([coord_x, coord_y])

        if not len(moves_allowed):
            self.send_error(400, explain="No allowed moves found")
            return

        move = random.choice(moves_allowed)

        self.send_json_response({'move': move})

    def do_finish(self, _):
        """Process 'finish' command.

        https://lostcode.io/docs/tic-tac-toe/api/finish/
        """
        self.send_empty_response()

    def do_error(self, _):
        """Process 'error' command.

        https://lostcode.io/docs/tic-tac-toe/api/error/
        """
        self.send_empty_response()

    def handle_one_request(self):
        """Handle a single HTTP request."""
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return

            if self.command != 'POST':
                error_text = "Only 'POST' HTTP methods are allowed"
                self.send_error(400, explain=error_text)
                return

            get_params = parse_qs(urlparse(self.path).query)
            if 'method' not in get_params:
                self.send_error(400, explain="No API method defined")
                return

            api_method = get_params['method'][0]
            method_name = f'do_{api_method}'
            if hasattr(self, method_name):
                cmd_method = getattr(self, method_name)
            else:
                error_text = f"Unsupported API method '{api_method}'"
                self.send_error(400, explain=error_text)
                return

            content_length = self.headers.get('content-length')
            if content_length:
                try:
                    content_length = int(content_length)
                except (ValueError, TypeError):
                    error_text = "'Content-Length' header is wrong"
                    self.send_error(400, explain=error_text)
                    return
            else:
                error_text = "'Content-Length' header is not defined"
                self.send_error(400, explain=error_text)
                return

            content_type_header = self.headers.get('content-type')
            if not content_type_header:
                error_text = "'Content-Type' header is not defined"
                self.send_error(400, explain=error_text)
                return

            content_type_parts = content_type_header.split(';')
            content_type = content_type_parts[0]
            if content_type != 'application/json':
                error_text = "Only 'JSON' requests are supported"
                self.send_error(400, explain=error_text)
                return

            try:
                request_data = json.loads(
                    str(self.rfile.read(content_length), 'utf-8')
                )
            except ValueError:
                self.send_error(400, explain="Can't parse JSON data")
                return

            cmd_method(request_data)
            self.wfile.flush()
        except socket.timeout as e:
            # a read or a write timed out, discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
            return


def create_handler(version: str, secret: str):
    def handler(*args):
        return SampleBot(version, secret, *args)
    return handler


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='sample_bot',
        description='Tic-tac-toe sample bot for LostCode.io',
    )
    parser.add_argument("-v", "--version", type=str, required=True)
    parser.add_argument("-s", "--secret", type=str, default=os.getenv("SECRET"))
    parser.add_argument("-p", "--port", type=int, default=8080)
    args = parser.parse_args()

    if not args.secret:
        print("Error: secret is not defined")
        parser.print_help()
        sys.exit(1)

    if not 1024 <= args.port <= 65535:
        print("Error: port number must be in range 1024-65535")
        parser.print_help()
        sys.exit(1)

    try:
        httpd = http.server.HTTPServer(
            ('localhost', args.port),
            create_handler(args.version, args.secret),
        )
        httpd.version = args.version
        httpd.secret = args.secret
    except OSError as exc:
        print(f"Error: {exc}")
        parser.print_help()
        sys.exit(1)

    print(f"Starting 'Tic tac toe' sample bot server version {args.version} at port {args.port}.")
    print("Quit the server with CONTROL-C.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('CONTROL-C received, shutting down server')
        httpd.socket.close()
