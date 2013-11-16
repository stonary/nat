import SimpleHTTPServer
import SocketServer

class CSC458Handler(SimpleHTTPServer.SimpleHTTPRequestHandler):

    # Disable logging DNS lookups
    def address_string(self):
        return str(self.client_address[0])


PORT = 80

Handler = CSC458Handler
httpd = SocketServer.TCPServer(("", PORT), Handler)
print "Server2: httpd serving at port", PORT
httpd.serve_forever()
