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

import sys
import os
import argparse
import subprocess
import logging
import json

# get currewnt logged in USER Home
loggedin_user  = os.path.expanduser('~')

executable_name = 'terrascan'

def check_executable(executable_name):

    """
    Takes an executable name as input and checks if it is installed.

    Input: 
        - executable_name : string
    Output: True if the executable is installed, False otherwise
    """

    try:
        subprocess.check_output(['which', executable_name])
        return True
    except subprocess.CalledProcessError:
        return False

def get_terrascan():

    """
    Download and install Terrascan on the system.

    Input: N/A
    Output: Boolean value; True if Terrascan is succesfully installed, False otherwise
    """

    os.system('curl -L "$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest | grep -o -E "https://.+?_Linux_x86_64.tar.gz")" > terrascan.tar.gz')
    os.system('tar -xf terrascan.tar.gz terrascan && rm terrascan.tar.gz')
    os.system('install terrascan /usr/local/bin && rm terrascan')
    return check_executable('terrascan')

def get_scan_results(terraform_file):

    """
    Takes a Terraform file details as input and scans it for misconfigurations by checking against selected policies.

    Input: 
        - terraform_file : string
    Output: Returns a dictionary with following keys:
    - policies_validated : no of policies scanned
    - violated_policies : no of scanned policies that were violated
    - pie_chart_data : list of dictionaries with high, medium, and low data to be used for generating pie plot
    - high : high risk violations
    - medium : medium risk violations
    - low : low risk violations
    """

    if check_executable(executable_name):
        print(f"{executable_name} is installed.")
    else:
        print(f"{executable_name} is not installed.")
        logging.info(f"Terrascan is not installed. Calling installer.")
        if get_terrascan():
            print('Succesfully installed Terrascan..!')
            logging.info(f"Terrascan is successfully installed.")
        else:
            logging.error("Failed to install Terrascan..!")

    violations = []
    scan_cmd = f"terrascan scan -f {terraform_file} -o json > temp.json"
    os.system(scan_cmd)
    with open('temp.json', 'r') as scan_result_file:
        return scan_result_file
        scan_result = json.loads(scan_result_file.read())
    scan_summary = scan_result['results']['scan_summary']
    policies_validated = scan_summary['policies_validated']
    violated_policies = scan_summary['violated_policies']
    low = scan_summary['low']
    medium = scan_summary['medium']
    high = scan_summary['high']
    if violated_policies != 0:
        violations = scan_result['results']['violations']
    os.system('rm temp.json')
    pie_chart_data = [{ "title": 'Low', "value": low, "color": '#90EE90' }, { "title": 'Medium', "value": medium, "color": '#e3df50'}, { "title": 'High', "value": high, "color": '#F75D59' }]
    return {"policies_validated" : policies_validated, "violated_policies" : violated_policies, "pie_chart_data" : pie_chart_data, "high" : high, "medium" : medium, "low" : low, "violations" : violations}

# Command line argument parser
def createParser():
    # Create the parser
    parser = argparse.ArgumentParser()
    # Add arguments
    parser.add_argument('--file', type=str, required=True, help="Path of Terraform file")
    return parser

if __name__=="__main__":
    parser = createParser()

    # Parse the argument
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    terraform_file = args.file
    # Store check results in a local variable
    result = ""
    
    # Check if Terrascan is not installed
    executable_name = 'terrascan'
    if check_executable(executable_name):
        print(f"{executable_name} is installed.")
    else:
        print(f"{executable_name} is not installed.")
        logging.info(f"Terrascan is not installed. Calling installer.")
        if get_terrascan():
            print('Succesfully installed Terrascan..!')
            logging.info(f"Terrascan is successfully installed.")
        else:
            logging.error("Failed to install Terrascan..!")

    result = get_scan_results(terraform_file)
    print(result)