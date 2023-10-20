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

import docker
import os
import re
import json
import argparse

available_dockers = ['ubuntu','red hat','kali']


def rootDirectory():
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    return ROOT_DIR

def get_algos(scan_os):

    """
    Takes an OS name as input and finds all cipher suite details natively supported on it.

    Input: 
        - scan_os : string
    Output: Returns two details:
        - String of scan result source details
        - Dictionary of cipher algorithm details
    """

    parsed_algorithm_info = {}
    if scan_os in available_dockers:
        if scan_os == "ubuntu":
          
            parsed_algorithm_info = "rootDirectory()"
        elif scan_os == "red hat":
            with open('/microservices/file_system_info/red_hat.json') as redhat:
                crypto_content = json.loads(redhat.read())
            parsed_algorithm_info = crypto_content
        elif scan_os == "kali":
            with open('/microservices/file_system_info/kali.json') as kali:
                crypto_content = json.loads(kali.read())
            parsed_algorithm_info = crypto_content
        return "/proc/crypto on latest docker image", parsed_algorithm_info
    else:
        if scan_os == "windows":
            # Read from existing information about cryptographic algorithms supported on Windows
            with open('/microservices/file_system_info/windows_info.txt', 'r') as windows_info_file:
                for line in windows_info_file.readlines():
                    # readlines preserves next line character, so while tokenizing each line we need to remove the line terminator
                    extracted_info = line[:-1].split(',')
                    parsed_algorithm_info[extracted_info[0]] = [extracted_info[1], extracted_info[2]]
            return "https://learn.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation?source=recommendations", parsed_algorithm_info
        # Display details for supported cryptographic algorithms on the target OS version
        # print(f"Supported cryptographic algorithms on {scan_os}:")
        # for algorithm in algorithm_details.keys():
        #     if scan_os.lower() in algorithm_details[algorithm].lower():
        #         print(f"{algorithm}: {algorithm_details[algorithm]}")
        return "'cryptography' library", parsed_algorithm_info
    
def createParser():
    # Create the parser
    parser = argparse.ArgumentParser()
    # Add arguments
    parser.add_argument('--os', type=str, required=True)
    return parser

if __name__=='__main__':
    parser = createParser()
    # Parse the argument
    args = parser.parse_args()
    scan_target = args.os
    scan_results = get_algos(scan_target)

    print(scan_results)