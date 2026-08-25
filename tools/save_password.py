# -*- coding: utf-8 -*-
################################
# File Name   : save_password.py
# Author      : liyanqing
# Created On  : 2021-08-16 20:11:25
# Description :
################################
import os
import sys
import getpass
import argparse

sys.path.append(os.environ['BATCH_RUN_INSTALL_PATH'])
sys.path.append(os.path.join(os.environ['BATCH_RUN_INSTALL_PATH'], 'common'))
from common import common_secure
from config import config

USER = getpass.getuser()
os.environ['PYTHONUNBUFFERED'] = '1'


def read_args():
    """
    Read in arguments.

    Password is resolved in priority order:
      1. -p/--password (discouraged: visible in argv/ps/shell history);
      2. the BATCH_RUN_PASSWORD environment variable;
      3. an interactive getpass() prompt (preferred for manual use).
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--password',
                        default='',
                        help='Specify user password. Avoid passing passwords on the command line; '
                             'prefer the BATCH_RUN_PASSWORD env var or the interactive prompt.')
    parser.add_argument('-H', '--host',
                        default='default',
                        help='Specify the host which user password works on, default is "default".')
    parser.add_argument('-o', '--output_file',
                        default='',
                        help='Specify the output file, default is "<db_path>/password/<user>".')

    args = parser.parse_args()

    if not args.output_file:
        args.output_file = str(config.db_path) + '/password/' + str(USER)

    password_dir_path = os.path.dirname(args.output_file)

    if not os.path.exists(password_dir_path):
        try:
            os.makedirs(password_dir_path)
            os.chmod(password_dir_path, 0o700)
        except Exception as error:
            print('*Error*: Failed on creating password directory "' + str(password_dir_path) + '", ' + str(error))
            sys.exit(1)

    # Resolve password without leaking it through argv/ps where possible.
    password = args.password or os.environ.get('BATCH_RUN_PASSWORD', '')

    if not password:
        try:
            password = getpass.getpass('Please input password for host "' + str(args.host) + '": ')
        except Exception as error:
            print('*Error*: Failed on reading password interactively: ' + str(error))
            sys.exit(1)

    if not password:
        print('*Error*: Empty password, nothing to save.')
        sys.exit(1)

    return (password, args.host, args.output_file)


################
# Main Process #
################
def main():
    (password, host, output_file) = read_args()
    my_save_and_get_password = common_secure.SaveAndGetPassword()
    my_save_and_get_password.save_password(output_file, password, USER, host)


if __name__ == '__main__':
    main()
