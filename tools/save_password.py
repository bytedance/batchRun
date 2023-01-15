#!/bin/env python3
# -*- coding: utf-8 -*-
################################
# File Name   : save_password.py
# Author      : liyanqing
# Created On  : 2021-08-16 20:11:25
# Description :
################################
import os
import re
import sys
import argparse

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common_password

os.environ['PYTHONUNBUFFERED'] = '1'


def read_args():
    """
    Read in arguments.
    """
    current_user = os.popen('whoami').read().strip()
    parser = argparse.ArgumentParser()

    parser.add_argument('-P', '--password_file',
                        default=str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config/password.encrypted',
                        help='Specify the user password file, default is "' + str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config/password.encrypted".')
    parser.add_argument('-u', '--user',
                        default=current_user,
                        help='Specify user name, deault is current user.')
    parser.add_argument('-p', '--password',
                        required=True,
                        default='',
                        help='Specify user password.')
    parser.add_argument('-H', '--host',
                        default='',
                        help='Specify the host which user password is for, default is for all hosts.')

    args = parser.parse_args()

    return(args.password_file, args.user, args.password, args.host)


class SavePassword():
    def __init__(self, password_file, user, password, host):
        self.password_file = password_file
        self.user = user
        self.password = password
        self.host = host

        self.user_dic = {}

    def get_user_dic(self):
        if os.path.exists(self.password_file):
            with open(self.password_file, 'r') as PF:
                for line in PF.readlines():
                    if re.match('^\s*$', line) or re.match('^\s*#.*$', line):
                        continue
                    elif re.match('^\s*(\S+?)\s+(\S+)\s*(\S+)?\s*$', line):
                        my_match = re.match('^\s*(\S+?)\s+(\S+)\s*(\S+)?\s*$', line)
                        user = my_match.group(1)
                        password = my_match.group(2)
                        host = my_match.group(3)

                        if not host:
                            host = ''

                        if user in self.user_dic.keys():
                            self.user_dic[user].append({'password': password, 'host': host})
                        else:
                            self.user_dic[user] = [{'password': password, 'host': host}, ]

    def check_user_dic(self):
        if self.user in self.user_dic.keys():
            for user_dic in self.user_dic[self.user]:
                if self.host == user_dic['host']:
                    if self.host:
                        print('*Error*: user "' + str(self.user) + '" and host "' + str(self.host) + '" is defined repeatedly on "' + str(self.password_file) + '".')
                    else:
                        print('*Error*: user "' + str(self.user) + '" is defined repeatedly on "' + str(self.password_file) + '".')

                    sys.exit(1)

    def write_user_password(self):
        try:
            with open(self.password_file, 'a') as PF:
                encrypted_password = common_password.encrypt(self.password)
                PF.write(str(self.user) + '  ' + str(encrypted_password) + '  ' + str(self.host) + '\n')
        except Exception as error:
            print('*Error*: Failed on open file "' + str(self.password_file) + '" for write, ' + str(error))
            sys.exit(1)

    def run(self):
        self.get_user_dic()
        self.check_user_dic()
        self.write_user_password()


################
# Main Process #
################
def main():
    (password_file, user, password, host) = read_args()
    my_save_password = SavePassword(password_file, user, password, host)
    my_save_password.run()


if __name__ == '__main__':
    main()
