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

from git import RemoteProgress
from subprocess import PIPE, Popen
import git
import logging
import os
import json
import argparse

""""
The Crypto-detector API is integrated in this project. For m ore details please visit: https://github.com/Wind-River/crypto-detector
The scan-for-crypto.py is the main file and triggered by subprocess in python.
This method returns any crypto key wods are matched in the reponame as JSON object. It scans only the source files only. If no crypto key words found the methid return None as string.
"""

# get currewnt logged in USER Home
loggedin_user  = os.path.expanduser('~')

# Verifying crypto-detector is available in the Home dir
crypto_detector_path = f'{loggedin_user}/crypto-detector/'
gitrepo_dir = loggedin_user+'/gitrepo/data/'

# Latest NIST Asymetric algorithms list - https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022
asymmetric_crpypto = ['CRYSTALS-KYBER', 'CRYSTALS-DILITHIUM', 'FALCON', 'SPHINCS+', 'SHA', 'AES']

logging.basicConfig(level=logging.DEBUG)

class CloneProgress(RemoteProgress):
    def update(self, op_code, cur_count, max_count=None, message=''):
        if message:
            print(message)

def url_validation(repo_name):
    url = ''
    if 'https://github.com/' in repo_name and len(repo_name.split('/', 5)) >= 5:
            if '.git' in repo_name:
                url = repo_name.replace(".git", "")
                url = "/".join(url.split('/',5)[3:5])
                return url
            else:
                url = repo_name
                url = "/".join(url.split('/',5)[3:5])
                return url
    else:
        return None

def clone(repo, local_path):
    logging.info('Cloning into %s' % repo)
    try:
        git.Repo.clone_from(repo, local_path, branch='master', progress=CloneProgress())
    except ConnectionError:
        print("Connection failed!!")
        raise ConnectionError

def getCryptoDetector():
    if not os.path.exists(crypto_detector_path):
        logging.info(f"crypto-detector not found in {loggedin_user}")
        logging.info("Cloning: https://github.com/Wind-River/crypto-detector")
        clone("https://github.com/Wind-River/crypto-detector.git", crypto_detector_path)
    else:
        logging.info(f"crypto-detector found in {loggedin_user}")
    logging.info("Proceeding to scan")
    return

def scan(repo):
    owner, reponame = repo.split('/')
    sbom_cmd = f'{crypto_detector_path}scan-for-crypto.py -v false --keyword-ignore-case --methods=keyword,api -c {crypto_detector_path}cryptodetector.conf {gitrepo_dir}{reponame} --source-files-only=True  --output-existing=overwrite -o {gitrepo_dir} '
    print(sbom_cmd)
    capture_cmd_result = Popen(sbom_cmd, stdout=PIPE, shell=True)
    flag = capture_cmd_result.communicate()[0].decode('utf-8').split() 
    if 'done' in flag:
        detectors = []
        detect_file = f"{gitrepo_dir}{reponame}.crypto"
        with open(detect_file) as file:
            detectorObj = json.loads(file.read())
        root_file = detectorObj['crypto_evidence']
        if len(root_file) > 0:
            git_url = f"https://github.com/{owner}/{reponame}"
            safe = 0
            unsafe = 0
            need_to_work = 0
            risk_factor_safe = 0
            risk_factor_unsafe = 0
            risk_factor_needtowork = 0
            global_risk_factor = 0
            for files in root_file:
                for item in root_file[files]['hits']:
                    for file_path in root_file[files]['file_paths']:
                        temp_path = file_path.split('/', 6)[-1]
                        gitPath = f"{git_url}/blob/main/{temp_path}/#L{item['line_number']}"
                        if 'asymmetric' in item['evidence_type'].lower()  or 'hash' in item['evidence_type'].lower() or 'aes' in item['evidence_type'].lower() :
                            detectors.append({
                                        'file_path': gitPath,
                                        'evidence_type': item['evidence_type'],
                                        'matched_text': item['matched_text'],
                                        'quantum_safe': 'Yes'
                            })
                            safe += 1
                            risk_factor_safe += 0.1
                        elif 'symmetric' in item['evidence_type'].lower() and not 'aes' in item['evidence_type'].lower():
                            detectors.append({
                                        'file_path': gitPath,
                                        'evidence_type': item['evidence_type'],
                                        'matched_text': item['matched_text'],
                                        'quantum_safe': 'No'
                            })
                            unsafe += 1
                            risk_factor_unsafe += 1
                        else:
                            detectors.append({
                                        'file_path': gitPath,
                                        'evidence_type': item['evidence_type'],
                                        'matched_text': item['matched_text'],
                                        'quantum_safe': 'No'
                            })
                            unsafe += 1
                            risk_factor_needtowork += 1
            if safe != 0 or unsafe != 0:
                global_risk_factor = risk_factor_unsafe/(safe+unsafe)
            stats = [{'Safe': safe, 'Unsafe': unsafe}]
            #pie_chart_data = [{'values': [safe, unsafe], 'labels': ['Safe', 'Unsafe'], 'type': 'pie'}]
            pie_chart_data = [{ "title": 'safe', "value": safe, "color": '#90EE90' }, { "title": 'unsafe', "value": unsafe, "color": '#F75D59' }]
            #print(pie_chart_data)

            return [detectors, pie_chart_data, stats, global_risk_factor]
        else:
            return "None"
    else:
        return flag

def scan_repo(repo):
    # Check if crypto-checker is present, download otherwise
    getCryptoDetector()

    # Initiate scan against the repo
    # Validate repository URL provided as user input 
    url = url_validation(repo)
    if url:
        # Check git_repo dir exists 
        isGitrepos = os.path.exists(gitrepo_dir)
        
        if not isGitrepos:
            os.makedirs(gitrepo_dir, exist_ok=True)
            logging.info(f"Default directory paths: {gitrepo_dir}")
        else:
            logging.info(f"Default directory already exists: {gitrepo_dir}")

        # If repository has already been cloned, remove it before cloning    
        repo_name = url.split('/')[-1]     
        if os.path.exists(f"{gitrepo_dir}{repo_name}"):
            logging.info("Previosuly cloned instance found. Removing before proceeding.")
            cmd = f"rm -rf {gitrepo_dir}{repo_name}"
            os.system(cmd)

        logging.info("Cloning Git repo: "+repo_name)
        clone(repo,f"{gitrepo_dir}{repo_name}")
    return scan(url)

def createParser():
    # Create the parser
    parser = argparse.ArgumentParser()
    # Add arguments
    parser.add_argument('--repo', type=str, required=True)
    return parser

if __name__=='__main__':
    parser = createParser()
    # Parse the argument
    args = parser.parse_args()
    scan_target = args.repo
    scan_results = scan_repo(scan_target)

    print(scan_results)

#print(scan_repo('https://github.com/prateek22/atlantis.git'))