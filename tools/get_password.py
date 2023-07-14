# -*- coding: utf-8 -*-
################################
# File Name   : get_password.py
# Author      : liyanqing
# Created On  : 2021-08-21 16:56:31
# Description :
################################
import os
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
                        help='Specify the user name，default is current user.')
    parser.add_argument('-H', '--host',
                        default='',
                        help='Specify the host which user password is for, default is for all hosts.')

    args = parser.parse_args()

    if not os.path.exists(args.password_file):
        print('*Error*: ' + str(args.password_file) + ': No such file.')
        sys.exit(1)

    return (args.password_file, args.user, args.host)


################
# Main Process #
################
def main():
    (password_file, user, host) = read_args()
    decrypted_password = common_password.get_password(password_file, user, host)

    print(decrypted_password)


if __name__ == '__main__':
    main()
