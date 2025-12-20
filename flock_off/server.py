# THIS MODULE WILL BE RESPONSIBLE FOR LAUNCHING WEB SERVER

from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import threading
import os

# Global variable to store AI cameras data that gets updated from flock_finder
ai_cameras_data = {"wifi": [], "ble": []}

class CameraHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler to serve GUI files and camera data"""

    def do_GET(self):
        """Handle GET requests - either serve API data or static files"""

        # If the request is for camera data, return JSON
        if self.path == '/api/cameras':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')  # Allow cross-origin requests
            self.end_headers()
            # Send the camera data as JSON
            self.wfile.write(json.dumps(ai_cameras_data).encode())
        else:
            # For all other requests, serve static files (HTML, CSS, JS) from gui directory
            super().do_GET()

class Web_Server():
    """This will control the web server"""

    server = None

    @staticmethod
    def update_data(data):
        """Update the camera data from flock_finder - call this to refresh the data"""
        global ai_cameras_data
        ai_cameras_data = data

    @staticmethod
    def start(port=8000):
        """Start the web server in a separate thread"""

        # Get the absolute path to the gui directory (one level up from flock_off)
        current_dir = os.path.dirname(os.path.abspath(__file__))  # Gets /flock_off directory
        gui_path = os.path.join(current_dir, '..', 'gui')  # Goes up one level to /gui
        gui_path = os.path.abspath(gui_path)  # Convert to absolute path

        # Change working directory to gui folder so HTTP server serves those files
        os.chdir(gui_path)

        # Create HTTP server on specified port
        server_address = ('', port)
        Web_Server.server = HTTPServer(server_address, CameraHTTPRequestHandler)

        # Start server in background thread so it doesn't block main program
        threading.Thread(target=Web_Server.server.serve_forever, daemon=True).start()

        # Print server info
        print(f"[+] Web server started on http://localhost:{port}")
        print(f"[+] Serving GUI from: {gui_path}")
        print(f"[+] API endpoint: http://localhost:{port}/api/cameras")
