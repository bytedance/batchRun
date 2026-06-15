import os
import re
import sys
import time
import getpass
import hashlib

import pexpect
import common_secure_key

VERSION = '2024.12.24'


class SaveAndGetPassword():
    def __init__(self, debug=False):
        self.debug = debug

    def debug_print(self, message):
        if self.debug:
            print(message)

    def __parse_password_file(self, password_file):
        """
        The line format of password file must be as below:
        <user>  <host>  <second>  <password>  <md5>
        """
        password_dic = {}

        if os.path.exists(password_file):
            try:
                with open(password_file, 'r') as PF:
                    for line in PF.readlines():
                        if re.match(r'^(\S+)  (\S+)  (\d+)  (\S+)  (\S+)$', line):
                            my_match = re.match(r'^(\S+)  (\S+)  (\d+)  (\S+)  (\S+)$', line)
                            user = my_match.group(1)
                            host = my_match.group(2)
                            second = my_match.group(3)
                            password = my_match.group(4)
                            md5 = my_match.group(5)
                            key_info = str(user) + str(host) + str(second) + str(password)
                            check_md5 = hashlib.md5(key_info.encode()).hexdigest()

                            if check_md5 != md5:
                                try:
                                    os.remove(password_file)
                                    break
                                except Exception as error:
                                    self.debug_print('*Error*: Failed on removing file "' + str(password_file) + '": ' + str(error))

                            password_dic.setdefault(user, {})

                            if host not in password_dic[user]:
                                password_dic[user][host] = {'second': second, 'password': password}
                            else:
                                self.debug_print('*Warning*: Repeated user/host setting on password file for below line, ignore.')
                                self.debug_print('           ' + str(line.strip()))
            except Exception as error:
                self.debug_print('*Error*: Failed on opening file "' + str(password_file) + '" for read, ' + str(error))

        return password_dic

    def __check_user_permission(self, user, mode):
        """
        Permission check pass only for below condition:
        * (user == current_user == login_user)
        * (user == current_user) and (login_uer == '')
        """
        login_user = os.popen("who am i | awk '{print $1}'").read().strip()
        current_user = os.popen('whoami').read().strip()

        if (user == current_user == login_user) or ((user == current_user) and (login_user == '')):
            return True
        else:
            self.debug_print('*Error*: ' + str(mode) + ' password fail, make sure login_user/current_user/specified_user are the same.')
            return False

    def save_password(self, password_file, password, user='', host='default'):
        if not user:
            user = getpass.getuser()

        if self.__check_user_permission(user, 'save'):
            password_dic = self.__parse_password_file(password_file)

            if user not in password_dic:
                password_dic.setdefault(user, {})

            current_second = str(int(time.time()))
            encrypted_password = common_secure_key.encrypt_password(user, host, current_second, password)
            password_dic[user][host] = {'second': current_second, 'password': encrypted_password}

            try:
                with open(password_file, 'w') as PF:
                    for user in password_dic.keys():
                        for host in password_dic[user].keys():
                            second = password_dic[user][host]['second']
                            password = password_dic[user][host]['password']
                            key_info = str(user) + str(host) + str(second) + str(password)
                            md5 = hashlib.md5(key_info.encode()).hexdigest()

                            PF.write(str(user) + '  ' + str(host) + '  ' + str(second) + '  ' + str(password) + '  ' + str(md5) + '\n')

                    os.chmod(password_file, 0o700)
            except Exception as error:
                self.debug_print('*Error*: Failed on opening file "' + str(password_file) + '" for write, ' + str(error))

    def get_password(self, password_file, user='', host='default'):
        decrypted_password = ''

        if not user:
            user = getpass.getuser()

        if self.__check_user_permission(user, 'get'):
            password_dic = self.__parse_password_file(password_file)

            if user not in password_dic:
                self.debug_print('*Error*: Not find password information for user "' + str(user) + '" on license file "' + str(password_file) + '".')
            else:
                if host not in password_dic[user]:
                    host = 'default'

                decrypted_password = common_secure_key.decrypt_password(user, host, password_dic[user][host]['second'], password_dic[user][host]['password'])

        return decrypted_password


def get_password(user, host, password):
    if not password:
        if 'BATCH_RUN_INSTALL_PATH' in os.environ:
            sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
            import config

            password_file = str(config.db_path) + '/password/' + str(user)

            if os.path.exists(password_file):
                my_save_and_get_password = SaveAndGetPassword()
                password = my_save_and_get_password.get_password(password_file, user, host)

    return password


def login_run(run_command, user, host, password, timeout=10):
    """
    For the scenarios that require logging into the server with a user/password to run.
    Typical scenarios are "ssh" and "scp".
    """
    stdout_list = []

    try:
        child = pexpect.spawn(run_command, timeout=timeout)
        expect_list = ['assword:', pexpect.EOF]
        index = child.expect(expect_list)

        if index == 0:
            password = get_password(user, host, password)
            child.sendline(password)
            stdout = child.read()
        else:
            stdout = child.before

        if stdout:
            stdout_list = str(stdout, 'utf-8').strip().split('\n')
    except Exception as warning:
        stdout_list = str(warning).split('\n')

    return stdout_list


def ssh_run(ssh_command, user, host, password, timeout=10):
    stdout_list = login_run(ssh_command, user, host, password, timeout)
    return stdout_list


def scp_run(scp_command, user, host, password, timeout=10):
    stdout_list = login_run(scp_command, user, host, password, timeout)
    return stdout_list
