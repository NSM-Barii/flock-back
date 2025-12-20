# THIS MODULE WILL BE RESPONSIBLE FOR LAUNCHING WEB SERVER

from http.server import HTTPServer, SimpleHTTPRequestHandler
import json, os, threading; from pathlib import Path



# NSM IMPORTS
from flock_finder import Main_Thread


cameras = Main_Thread.ai_cameras_all

class CameraHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler to serve GUI files and camera data"""

    def do_GET(self):
        """Handle GET requests - either serve API data or static files"""

        # If the request is for camera data, return JSON
        if self.path == '/api/cameras':


            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", '*')
            self.end_headers()

            # Send the camera data as JSON
            self.wfile.write(json.dumps(cameras).encode())


        else: super().do_GET()


class Web_Server():
    """This will control the web server"""

    server = None


    @staticmethod
    def start(port=8000):
        """Start the web server in a separate thread"""

        current_dir = os.path.dirname(os.path.abspath(__file__))  # Gets /flock_off directory
        gui_path = os.path.join(current_dir, '..', 'gui')  # Goes up one level to /gui
        gui_path = os.path.abspath(gui_path)  # Convert to absolute path


        gui_path = str(Path(__file__).parent.parent / "gui") 

        os.chdir(gui_path)

        server_address = ('', port)
        Web_Server.server = HTTPServer(server_address, CameraHTTPRequestHandler)

        print(f"[+] Web server started on http://localhost:{port}")
        #print(f"[+] Serving GUI from: {gui_path}")
        #print(f"[+] API endpoint: http://localhost:{port}/api/cameras")
        
        Web_Server.server.serve_forever()
 