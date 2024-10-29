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
from common import common_secure
from config import config

USER = getpass.getuser()
os.environ['PYTHONUNBUFFERED'] = '1'


def read_args():
    """
    Read in arguments.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--password',
                        required=True,
                        help='Specify user password.')
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
            os.chmod(password_dir_path, 0o1777)
        except Exception as error:
            print('*Error*: Failed on creating password directory "' + str(password_dir_path) + '", ' + str(error))
            sys.exit(1)

    return (args.password, args.host, args.output_file)


################
# Main Process #
################
def main():
    (password, host, output_file) = read_args()
    my_save_and_get_password = common_secure.SaveAndGetPassword()
    my_save_and_get_password.save_password(output_file, password, USER, host)


if __name__ == '__main__':
    main()
