# batchRun V1.2

## Update history
***
| Version | Date      | Update content                             |
|:--------|:----------|:-------------------------------------------|
| V1.0    | (2022.12) | Release original version.                  |
| V1.1    | (2023.07) | Support host_ip & host_name multi-mapping. |
|         |           | Remove LSF supporting.                     |
| V1.2    | (2024.08) | Add host info sampling function.           |


## Introduction
***

### 0. What is batchRun?
batchRun is an open source IT automation engine, which is used 
for task push and information retrieval across multiple linux 
servers, just like pssh or ansible.

### 1. Python dependency
Need python3.8.8, Anaconda3-2021.05-Linux-x86_64.sh is better.
Install python library dependency with command

    pip install -r requirements.txt

### 2. Install
Copy install package into install directory.
Execute below command under install directory.

    python3 install.py

### 3. Config
  - Basic configuration  
    config/config.py : basic configuration.
  - Host informaiton  
    config/host.list : save the host and host_group
    information.
  - Encrypted user&password information  
    config/password.encrypted : save encrypted user/password  
    information, generate it with tool tools/save_password.


More details please see ["docs/batchRun_user_manual.pdf"](./docs/batchRun_user_manual.pdf)
