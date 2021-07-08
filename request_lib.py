"""
Created on 5 Jul 2017

@author: gavin
"""
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse
from logging.handlers import RotatingFileHandler
from io import StringIO
from urllib.parse import urlparse
from OpenSSL import SSL

import collections
import socket
import logging
import datetime
import hashlib
import http
import ssl

class RequestLogger(logging.Logger):
    REQUEST = 8    # used for logging the requests
    RESPONSE = 7   # used for logging the response
    
    def __init__(self, *args, **kwargs):
        super(RequestLogger, self).__init__(*args, **kwargs)
        logging.addLevelName(RequestLogger.REQUEST, 'REQUEST')
        logging.addLevelName(RequestLogger.RESPONSE, 'RESPONSE')
        self.setLevel(logging.INFO)
        
    def request(self, msg, *args, **kwargs):
        msg = "\n{}\n".format(msg.rstrip())
        self.log(RequestLogger.REQUEST, msg, *args, **kwargs)
        
    def response(self, msg, *args, **kwargs):
        "\n{}\n".format(msg.rstrip())
        self.log(RequestLogger.RESPONSE, msg, *args, **kwargs)

logging.setLoggerClass(RequestLogger)
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', datefmt='%d-%b-%y %H:%M:%S')
LOG = logging.getLogger(__name__)

class RawResponse(HTTPResponse):
    def __init__(self, *args, **kwargs):
        HTTPResponse.__init__(self, *args, **kwargs)
        self.raw = None
    
    def get_raw_response(self):
        """
        Reads the entire response as bytes
        """
        version = "HTTP/1.1"
        if self.version == 10:
            version = "HTTP/1.0"

        response = "{} {} {}\r\n{}\r\n{}\r\n".format(version, self.code, self.reason, self.headers, self.read().decode("utf-8"))
        self.raw = response.encode()
        LOG.debug("Read raw response")
        LOG.response(self.raw)
        return self.raw

    def get_raw_headers(self):
        """
        Return only headers
        """
        self.get_raw_response()
        return self.raw.split("\r\n\r\n", 1)

    def is_redirect(self):
        """
        True/False: Checks if its a redirect
        """
        location = self.getheader("Location")
        if len(location) > 0:
            return True
        return False

class RawRequest(HTTPConnection):
    """
    Represents a single raw request.
    Lets define our own HTTPSConnect code
    host, port=None, strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None
    """
    __all__ = [""]

    MAX_REDIRECTS = 3
     
    def __init__(self, host, port, raw, follow_redirect=False, is_ssl=False, verbose=0):
        HTTPConnection.__init__(self, host, port)
        self._set_log_level(verbose)
        self.response_class = RawResponse
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8") 
        self.rfile = StringIO(raw)
        self.timeout = 5
        self.method = None
        self.path = None
        self.version = None
        self.data = None
        self.checksum = None
        self.redirect_count = 0
        self.is_ssl = is_ssl
        self.is_proxy = False
        self.follow_redirect = follow_redirect
        if self.is_ssl is True:
            self.set_context()
        self.parse_request()
    
    def __key(self):
        return (self.host, self.port, self.rfile)
    
    def __hash__(self):
        return hash(self.__key())
    
    def __eq__(self, other):
        return self.__key() == other.__key()
    
    def __ne__(self, other):
        return self.__key() != other.__key()

    def _set_log_level(self, level):
        if level == 1:
            LOG.setLevel(logging.INFO)
        elif level == 2:
            LOG.setLevel(logging.DEBUG)
        elif level == 3:  
            LOG.setLevel(RequestLogger.REQUEST)
        elif level >= 4:  
            LOG.setLevel(RequestLogger.RESPONSE)
        else:
            LOG.setLevel(logging.CRITICAL)

    def _parse_headers(self, rawheaders):
        """
        Parses a raw request headers to ordered dictionary
        """
        self.headers = collections.OrderedDict()
        for line in rawheaders.split('\n'):
            if ":" in line:
                name, value = line.rstrip().split(':', 1)
                self.headers[name] = value.rstrip().lstrip()

    def _redirect(self, resp):
        """
        Follows a redirect
        """
        if resp.is_redirect() is True:
            u = urlparse(resp.getheader("Location"))
            LOG.debug("Redirect to - {}".format(resp.getheader("Location")))
            if len(u.netloc) == 0:
                self.path = u.path
            elif u.netloc == self.get_header("Host"):
                self.path = resp.getheader("Location").replace("{}://{}".format(u.scheme, u.netloc), "")
            else:
                LOG.debug("Ignoring redirect")
                return
            LOG.debug("Following - {} {}".format(self.host, self.path))
            self.send_request(connect=False)

    def set_timeout(self, timeout):
        """
        Overwrites the libaries timeout
        """
        self.timeout = timeout

    def set_context(self, context=None):
        """
        Setup a SSL context. Default is unverified
        """
        if context is None:
            # generate default context
            LOG.debug("Default SSL context created")
            context = ssl._create_unverified_context()
        self._context = context
        self._context.check_hostname = False
            
    def parse_request(self):
        """
        Parse the give raw request
        """
        requestline, rawheaders = self.rfile.getvalue().split('\n', 1)
        self.method, path, self.version = requestline.split(' ', 2)
        # parse data
        if '\n\n' in rawheaders:
            rawheaders, self.data = rawheaders.split('\n\n', 1)

        # Parse headers
        self._parse_headers(rawheaders)
        
        # parse query
        if '#' in path:
            self.path, ignore = path.split('#', 1)
        else:
            self.path = path
            
        s = (self.host + str(self.port) + self.rfile.getvalue()).encode('utf-8')
        self.checksum = hashlib.md5(s).hexdigest()

        LOG.debug("Parsed request")
            
    def set_verbose(self, level=0):
        """
        Turns on verbose within the class, prints raw requests
        """
        self._set_log_level(level)
        
    def validate(self):
        """
        Perform simple validation on request instance. Only basic as we'll likely be breaking rfc
        
        :return    bool    return True if passed validation
        """
        if self.method is not None and self.path is not None and self.version is not None:
            if self.version == 'HTTP/1.1':
                if len(self.get_header('Host')) > 0:
                    return True
            else:
                return True
        return False
    
    def get_header(self, name):
        """
        Get header by name
        
        :param     name: index of header name
        :returns:  header value from header list
        """
        try:
            headername = name.rstrip()
            return self.headers[headername]
        except KeyError:
            return None
        
    def add_header(self, name, value):
        """
        Adds a new header to list, small bit of validation performed
        
        :param    name: header name to overwrite supplied value
        :param    value: value to overwrite current value
        """
        self.headers[name.rstrip()] = value.rstrip()
    
    def add_data(self, data):
        """
        Adds contents to the POST data
        """
        self.data = self.data + data
        self._validate_request()
    
    def set_raw_request(self, raw):
        """
        Create a new raw request from provided details
        
        :param    raw: new raw string
        :return StringIO rawrequest
        """
        raw = StringIO(raw)
        self.rfile = raw
        self.parse_request()
    
    def get_raw_request(self):
        """
        Gets the raw request as a string
        
        :return    string of raw request
        """
        r = "%s %s %s\n" % (self.method, self.path, self.version)
        for h in self.headers:
            r = r + "%s: %s\n" % (h, self.headers[h])
        r = r + "\n"
        r = r + self.data
        r = r + "\n"
        self.rfile = StringIO(r)
        return self.rfile.getvalue()

    def set_hostname(self, hostname):
        """
        Sets the hostname in the headers list
        """
        self.add_header("Host", hostname)
        LOG.debug("Hostname set to - {}".format(hostname))
    
    def set_proxy(self, ip, port):
        """
        Reverse the host + port values, with ip and port
        """
        self.is_proxy = True
        self.set_tunnel(self.host, self.port)
        self.host = ip
        self.port = int(port)
        LOG.debug("Using proxy http://{}:{}".format(self.host, self.port))

    def connect(self):
        """
        Overwritten
        """
        super().connect()

        if self.is_ssl is True:
            if self._tunnel_host:
                server_hostname = self._tunnel_host
            else:
                server_hostname = self.host

            self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)

    def send_request(self, connect=True):
        """
        Connects with either HTTPConnection or HTTPSConnection
        """
        if connect is True:
            self.connect()
        LOG.info("{} {} {}".format(self.method, self.get_header("Host"), self.path))
        self.putrequest(self.method, self.path, skip_host=1, skip_accept_encoding=1)
        
        LOG.debug("Sending headers")
        for h in self.headers:
            self.putheader(h, self.headers[h])
        
        if self.data is None:
            self.endheaders()
        else:
            LOG.debug("Sending body")
            self.endheaders(message_body=str.encode(self.data)) ########### HERE ###############
        
        LOG.request(self.get_raw_request())

        response = self.getresponse()

        if self.follow_redirect is True and (response.code == 302 or response.code == 301) and self.redirect_count <= RawRequest.MAX_REDIRECTS:
            #look for Location header and check its the same domain
            self.redirect_count = self.redirect_count + 1
            self._redirect(response)
            
        # Close up connection
        self.sock = None
        self.close()
        return response
             
if __name__ == '__main__':
    raw = """GET / HTTP/1.1
Host: s1ipmonitoringservice.gmc-uk.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close


"""
    req = RawRequest('reward.gold.razer.com', 443, raw, is_ssl=True, follow_redirect=True)
    req.set_verbose(1)
    req.set_proxy('127.0.0.1', 8081)
    resp = req.send_request()
    resp.get_raw_response()
