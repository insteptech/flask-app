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

import argparse
import sys
import requests
from time import sleep
import xmltodict

def scan_aws(scan_target, scan_target_cloud_owner):
    key_info_response = requests.get(scan_target+"/?encryption", headers={"HOST" : scan_target, "x-amz-expected-bucket-owner" : scan_target_cloud_owner})
    key_info_xml = key_info_response.text
    try:
        key_info = xmltodict.parse(key_info_xml)
        if len(key_info['ServerSideEncryptionConfiguration']['Rule']) != 0:
            for rule in key_info['ServerSideEncryptionConfiguration']['Rule']:
                if rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == "AES256":
                    return {"cloud_target" : scan_target, "status" : "S3 Bucket encrypted using S3 default encryption", "algo" : "AES256", "pqc_secure" : "Yes"}
                else:
                    key_master_id = rule['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']
                    return {"cloud_target" : scan_target, "status" : f"S3 Bucket encrypted using AWS KMS (master key ID : {key_master_id})", "algo" : "AES-GCM-256", "pqc_secure" : "Yes"}
        else:
            return  {"cloud_target" : scan_target, "status" : f"S3 Bucket not encrypted", "algo" : "None", "pqc_secure" : "No"}
    except:
        return  {"cloud_target" : scan_target, "status" : f"Failed to access encryption details for the S3 bucket.", "algo" : "None", "pqc_secure" : "No"}


def get_scan_result(scan_target, scan_target_cloud_owner, scan_target_cloud_type):
    if scan_target_cloud_type == "s3":
        return scan_aws(scan_target, scan_target_cloud_owner)

# Command line argument parser
def createParser():
    # Create the parser
    parser = argparse.ArgumentParser()
    # Add arguments
    parser.add_argument('--target', type=str, required=True, help="Cloud target")
    parser.add_argument('--owner', type=str, required=True, help="Owner ID")
    parser.add_argument('--cloud-type', type=str, required=True, help="Cloud Provider Type")
    return parser

if __name__=="__main__":
    parser = createParser()

    # Parse the argument
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    scan_target = args.target
    scan_target_cloud_owner = args.owner
    scan_target_type = args.cloud_type

    if scan_target_type == "s3":
        print(scan_aws(scan_target, scan_target_cloud_owner))
