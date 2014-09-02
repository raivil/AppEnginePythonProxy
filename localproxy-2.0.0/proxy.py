#! /usr/bin/env python
# coding=utf-8

import daemon
import logging
import ConfigParser
from random import choice
import BaseHTTPServer, SocketServer, urllib, urllib2, urlparse, zlib, socket, os, common, sys, errno, base64, re
try:
    import ssl
    ssl_enabled = True
except:
    ssl_enabled = False

# global varibles
listen_port = common.DEF_LISTEN_PORT
last_fetch_server = 0
request_count = 0

class LocalProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    PostDataLimit = 0x100000

    def do_CONNECT(self):
        if not ssl_enabled:
            self.send_error(501, "Local proxy error, HTTPS needs Python2.6 or later.")
            self.connection.close()
            return

        # for ssl proxy
        (https_host, _, https_port) = self.path.partition(":")
        if https_port != "" and https_port != "443":
            self.send_error(501, "Local proxy error, Only port 443 is allowed for https.")
            self.connection.close()
            return

        # continue
        self.wfile.write("HTTP/1.1 200 OK\r\n")
        self.wfile.write("\r\n")
        ssl_sock = ssl.SSLSocket(self.connection, server_side=True, certfile=common.DEF_CERT_FILE, keyfile=common.DEF_KEY_FILE)

        # rewrite request line, url to abs
        first_line = ""
        while True:
            chr = ssl_sock.read(1)
            # EOF?
            if chr == "":
                # bad request
                ssl_sock.close()
                self.connection.close()
                return
            # newline(\r\n)?
            if chr == "\r":
                chr = ssl_sock.read(1)
                if chr == "\n":
                    # got
                    break
                else:
                    # bad request
                    ssl_sock.close()
                    self.connection.close()
                    return
            # newline(\n)?
            if chr == "\n":
                # got
                break
            first_line += chr
        # got path, rewrite
        (method, path, ver) = first_line.split()
        if path.startswith("/"):
            path = "https://%s" % https_host + path

        # connect to local proxy server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", listen_port))
        sock.send("%s %s %s\r\n" % (method, path, ver))

        # forward https request
        ssl_sock.settimeout(1)
        while True:
            try:
                data = ssl_sock.read(8192)
            except ssl.SSLError, e:
                if str(e).lower().find("timed out") == -1:
                    # error
                    sock.close()
                    ssl_sock.close()
                    self.connection.close()
                    return
                # timeout
                break
            if data != "":
                sock.send(data)
            else:
                # EOF
                break
        ssl_sock.setblocking(True)

        # simply forward response
        while True:
            data = sock.recv(8192)
            if data != "":
                ssl_sock.write(data)
            else:
                # EOF
                break

        # clean
        sock.close()
        ssl_sock.shutdown(socket.SHUT_WR)
        ssl_sock.close()
        self.connection.close()
   
    def do_METHOD(self):
        # check http method and post data
        method = self.command
        if method == "GET" or method == "HEAD":
            # no post data
            post_data_len = 0
        elif method == "POST":
            # get length of post data
            post_data_len = 0
            for header in self.headers:
                if header.lower() == "content-length":
                    post_data_len = int(self.headers[header])
                    break
            # exceed limit?
            if post_data_len > self.PostDataLimit:
                self.send_error(413, "Local proxy error, Sorry, Google's limit, file size up to 1MB.")
                self.connection.close()
                return
        else:
            # unsupported method
            self.send_error(501, "Local proxy error, Method not allowed.")
            self.connection.close()
            return

        # get post data
        post_data = ""
        if post_data_len > 0:
            post_data = self.rfile.read(post_data_len)
            if len(post_data) != post_data_len:
                # bad request
                self.send_error(400, "Local proxy error, Post data length error.")
                self.connection.close()
                return

        # do path check
        (scm, netloc, path, params, query, _) = urlparse.urlparse(self.path)
        if (scm.lower() != "http" and scm.lower() != "https") or not netloc:
            self.send_error(501, "Local proxy error, Unsupported scheme(ftp for example).")
            self.connection.close()
            return
        # create new path
        path = urlparse.urlunparse((scm, netloc, path, params, query, ""))

        # remove disallowed header
        dhs = []
        for header in self.headers:
            hl = header.lower()
            if hl == "if-range":
                dhs.append(header)
            elif hl == "range":
                dhs.append(header)
        for dh in dhs:
            del self.headers[dh]
        # create request for GAppProxy
        params = urllib.urlencode({"method": method,
                                   "encoded_path": base64.b64encode(path),
                                   "headers": base64.b64encode(str(self.headers)),
                                   "postdata": base64.b64encode(post_data),
                                   "version": common.VERSION})
        # accept-encoding: identity, *;q=0
        # connection: close
        request = urllib2.Request(self.req_count_fetch_server())
        request.add_header("Accept-Encoding", "identity, *;q=0")
        request.add_header("Connection", "close")
        opener = urllib2.build_opener()
        # set the opener as the default opener
        urllib2.install_opener(opener)
        try:
            resp = urllib2.urlopen(request, params)
        except urllib2.HTTPError, e:
            if e.code == 404:
                self.send_error(404, "Local proxy error, Fetchserver not found at the URL you specified, please check it.")
            elif e.code == 502:
                self.send_error(502, "Local proxy error, Transmission error, or the fetchserver is too busy.")
            else:
                self.send_error(e.code)
            self.connection.close()
            return
        except urllib2.URLError, e:
            self.connection.close()
            return

        # parse resp
        # for status line
        line = resp.readline()
        words = line.split()
        status = int(words[1])
        reason = " ".join(words[2:])

        # for large response
        if status == 592 and method == "GET":
            self.processLargeResponse(path)
            self.connection.close()
            return

        # normal response
        try:
            self.send_response(status, reason)
        except socket.error, (err, _):
            # Connection/Webpage closed before proxy return
            if err == errno.EPIPE or err == 10053: # *nix, Windows
                return
            else:
                raise

        # for headers
        text_content = True
        while True:
            line = resp.readline().strip()
            # end header?
            if line == "":
                break
            # header
            (name, _, value) = line.partition(":")
            name = name.strip()
            value = value.strip()
            # ignore Accept-Ranges
            if name.lower() == "accept-ranges":
                continue
            self.send_header(name, value)
            # check Content-Type
            if name.lower() == "content-type":
                if value.lower().find("text") == -1:
                    # not text
                    text_content = False
        self.send_header("Accept-Ranges", "none")
        self.end_headers()

        # for page
        if text_content:
            data = resp.read()
            if len(data) > 0:
                self.wfile.write(zlib.decompress(data))
        else:
            self.wfile.write(resp.read())
        self.connection.close()

    do_GET = do_METHOD
    do_HEAD = do_METHOD
    do_POST = do_METHOD

    def random_fetch_server(self):
        global last_fetch_server
        fetch_server = "http://oppuz-proxy.appspot.com/fetch.py"
        try:
            app_name = choice(fetch_server_list) #global
            fetch_server = "http://%(app_name)s.appspot.com/fetch.py" % locals()
            print "Composed Server : %s" % fetch_server
        except IndexError:
            fetch_server = "http://oppuz-proxy.appspot.com/fetch.py"
        return fetch_server

    # troca de app a cada requisição
    def ordered_fetch_server(self):
        global last_fetch_server
        fetch_server = "http://oppuz-proxy.appspot.com/fetch.py"
        try:
            if fetch_server_list[0] == '127.0.0.1':
                return 'http://127.0.0.1:8080/fetch.py'
            app_name = fetch_server_list[last_fetch_server]
            last_fetch_server = last_fetch_server + 1
            if last_fetch_server > (len(fetch_server_list) - 1):
                last_fetch_server = 0
            # last_fetch_server = (last_fetch_server-1 % len(fetch_server_list) ) + 1
            fetch_server = "http://%(app_name)s.appspot.com/fetch.py" % locals()
            # print "Composed Server : %s" % fetch_server
        except IndexError:
            fetch_server = "http://oppuz-proxy.appspot.com/fetch.py"
        return fetch_server

    #troca de app a cada 5000 requisições (numero aproximado de requests que ocorrem em 30 minutos, que é o tempo minimo de cobrança da instancia * 2)
    def req_count_fetch_server(self):
        global request_count
        fetch_server = "http://oppuz-proxy.appspot.com/fetch.py"
        try:
            request_count = request_count + 1
            if fetch_server_list[0] == '127.0.0.1':
                return 'http://127.0.0.1:8080/fetch.py'
            app_name = fetch_server_list[last_fetch_server]
            if request_count > 5000:
                request_count = 0
                last_fetch_server = last_fetch_server + 1
                if last_fetch_server > (len(fetch_server_list) - 1):
                    last_fetch_server = 0
            # last_fetch_server = (last_fetch_server-1 % len(fetch_server_list) ) + 1
            fetch_server = "http://%(app_name)s.appspot.com/fetch.py" % locals()
            # print "Composed Server : %s" % fetch_server
        except IndexError:
            fetch_server = "http://oppuz-proxy.appspot.com/fetch.py"
        return fetch_server

    def processLargeResponse(self, path):
        cur_pos = 0
        part_length = 0x100000 # 1m initial, at least 64k
        first_part = True
        content_length = 0
        text_content = True
        allowed_failed = 10

        while allowed_failed > 0:
            next_pos = 0
            self.headers["Range"] = "bytes=%d-%d" % (cur_pos, cur_pos + part_length - 1)
            # create request for GAppProxy
            params = urllib.urlencode({"method": "GET",
                                       "encoded_path": base64.b64encode(path),
                                       "headers": base64.b64encode(str(self.headers)),
                                       "postdata": base64.b64encode(""),
                                       "version": common.VERSION})
            # accept-encoding: identity, *;q=0
            # connection: close
            request = urllib2.Request(self.req_count_fetch_server())
            request.add_header("Accept-Encoding", "identity, *;q=0")
            request.add_header("Connection", "close")

            opener = urllib2.build_opener()
            # set the opener as the default opener
            urllib2.install_opener(opener)
            resp = urllib2.urlopen(request, params)

            # parse resp
            # for status line
            line = resp.readline()
            words = line.split()
            status = int(words[1])
            # not range response?
            if status != 206:
                # reduce part_length and try again
                if part_length > 65536:
                    part_length /= 2
                allowed_failed -= 1
                continue

            # for headers
            if first_part:
                self.send_response(200, "OK")
                while True:
                    line = resp.readline().strip()
                    # end header?
                    if line == "":
                        break
                    # header
                    (name, _, value) = line.partition(":")
                    name = name.strip()
                    value = value.strip()
                    # get total length from Content-Range
                    nl = name.lower()
                    if nl == "content-range":
                        m = re.match(r"bytes[ \t]+([0-9]+)-([0-9]+)/([0-9]+)", value)
                        if not m or int(m.group(1)) != cur_pos:
                            # Content-Range error, fatal error
                            return
                        next_pos = int(m.group(2)) + 1
                        content_length = int(m.group(3))
                        continue
                    # ignore Content-Length
                    elif nl == "content-length":
                        continue
                    # ignore Accept-Ranges
                    elif nl == "accept-ranges":
                        continue
                    self.send_header(name, value)
                    # check Content-Type
                    if nl == "content-type":
                        if value.lower().find("text") == -1:
                            # not text
                            text_content = False
                if content_length == 0:
                    # no Content-Length, fatal error
                    return
                self.send_header("Content-Length", content_length)
                self.send_header("Accept-Ranges", "none")
                self.end_headers()
                first_part = False
            else:
                while True:
                    line = resp.readline().strip()
                    # end header?
                    if line == "":
                        break
                    # header
                    (name, _, value) = line.partition(":")
                    name = name.strip()
                    value = value.strip()
                    # get total length from Content-Range
                    if name.lower() == "content-range":
                        m = re.match(r"bytes[ \t]+([0-9]+)-([0-9]+)/([0-9]+)", value)
                        if not m or int(m.group(1)) != cur_pos:
                            # Content-Range error, fatal error
                            return
                        next_pos = int(m.group(2)) + 1
                        continue

            # for body
            if text_content:
                data = resp.read()
                if len(data) > 0:
                    self.wfile.write(zlib.decompress(data))
            else:
                self.wfile.write(resp.read())

            # next part?
            if next_pos == content_length:
                return
            cur_pos = next_pos
    def log_message(self, format, *args):
        logging.info("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format%args))

class ThreadingHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    pass

def parseConf(confFile):
    global listen_port, fetch_server_list
    default_section = 'ProxyConfig'
    try:
        config = ConfigParser.ConfigParser()
        config.read(confFile)
        fetch_server_list = config.get(default_section,'fetch_server_list').split(',')
        listen_port = config.getint(default_section,'listen_port')
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise
        return

if __name__ == "__main__":
    parseConf(common.DEF_CONF_FILE)

    logging.info( "--------------------------------------------")
    logging.info( "HTTPS Enabled: %s" % (ssl_enabled and "YES" or "NO"))
    # logging.info( "Direct Fetch : %s" % (google_proxy and "NO" or "YES"))
    logging.info( "Listen Addr  : 127.0.0.1:%d" % listen_port)
    logging.info( "Fetch Server List : %s" % fetch_server_list)
    logging.info( "--------------------------------------------")
    httpd = ThreadingHTTPServer(("0.0.0.0", listen_port), LocalProxyHandler)
    # Make the context manager for becoming a daemon process.
    daemon_context = daemon.DaemonContext()
    daemon_context.files_preserve = [httpd.fileno()]
    logging.basicConfig(filename='/tmp/local_proxy.log',level=logging.DEBUG)

    print 'Iniciado proxy local em background:'

    # Become a daemon process.
    with daemon_context:
        httpd.serve_forever()