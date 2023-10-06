# Copyright 2023 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import socket
import ssl
import platform
import subprocess
import argparse
#import requests

#from OpenSSL import SSL, _util
#from itertools import count

def getHostCipherSuite():

    """
    Returns details of natively supported TLS cipher suites on a system.

    Input: N/A
    Output: Returns a dictionary with cipher_suite names as key and TLS protocol version as the value
    """

    os = platform.system()
    if os == 'Windows':
        process = subprocess.run(["powershell.exe", "Get-TlsCipherSuite | Format-Table -Property Name"], stdout=subprocess.PIPE)
        cmd_output = process.stdout.decode('utf-8')
        cipher_suite = [x.strip() for x in cmd_output.split('\n')[3:-3]]
    elif os == 'Linux':
        process = subprocess.run(["openssl", "ciphers", "-v"], stdout=subprocess.PIPE)
        cmd_output = process.stdout.decode('utf-8')
        cipher_suite = {x.split()[0]:x.split()[1] for x in cmd_output.split('\n')[:-1]}
    else:
        process = subprocess.run(["openssl", "ciphers", "-v"], stdout=subprocess.PIPE)
        cmd_output = process.stdout.decode('utf-8')
        cipher_suite = {x.split()[0]:x.split()[1] for x in cmd_output.split('\n')[:-1]}
    return cipher_suite

def getSharedCipherSuite(server):

    """
    Takes a remote server address as input and returns details of TLS cipher suites shared while initiating a TLS connection.

    Input: 
        - server : tuple of host address and port number
    Output: Returns a dictionary with shared cipher suites as keys and TLS protocol version as the value
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = ssl.wrap_socket(sock)
    ssl_sock.connect(server)
    return {x[0]:x[1] for x in ssl_sock.shared_ciphers()} # shared_ciphers returns cipher_suite sent by the client during tls handshake

def checkPQSafety(server):

    """
    Takes a remote server address and returns details of all cipher suites supported on the host and shared while creating TLS connection.

    Input: 
        - server : tuple of server address and port
    Output: Returns a dictionary with two keys:
    - host: dictionary of all natively supported cipher suites
    - shared: dictionary of all TLS cipher suites shared when a connection is initiated
    """

    host_cipher_suite = getHostCipherSuite()
    try:
        shared_cipher_suite = getSharedCipherSuite(server)
    except:
        shared_cipher_suite = host_cipher_suite
    return {"host" : host_cipher_suite, "shared" : shared_cipher_suite}


def createParser():
    # Create the parser
    parser = argparse.ArgumentParser()
    # Add arguments
    parser.add_argument('--host', type=str, required=True)
    parser.add_argument('--port', type=str, default="443")
    return parser

if __name__=='__main__':
    parser = createParser()
    # Parse the argument
    args = parser.parse_args()
    scan_target = args.host
    scan_target_port = int(args.port)
    scan_results = checkPQSafety((scan_target, scan_target_port))
    print(scan_results)

#print(checkPQSafety(("ec2-35-80-145-71.us-west-2.compute.amazonaws.com",3306)))
""" api_host = 'http://10.200.102.145:5000/getAPISecurity'
response = requests.post(api_host,json={"host":'127.0.0.1',"port":'3306',"protocol":'mysql'}) 
is_host_safe = "yes" if response.json()['tls_check']['is_safe']==True else "no"
print("Is API secure:" + is_host_safe)
print('Identified TLS Algorithms')
print('=========================')
print(response.json()['tls_check']['tls_algo_record'])
print('Vulnerabilties')
print('==============')
print(response.json()['vulnerabilties']) """
