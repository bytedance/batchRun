# -*- coding: utf-8 -*-
################################
# File Name   : run_ssh_command.py
# Author      : liyanqing
# Created On  : 2022-09-04 15:39:04
# Description :
################################
import os
import argparse
import pexpect

os.environ['PYTHONUNBUFFERED'] = '1'


def read_args():
    """
    Read in arguments.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', '--ssh_command',
                        required=True,
                        help='Specify the ssh command.')
    parser.add_argument('-H', '--host',
                        required=True,
                        help='Specify the ssh host.')
    parser.add_argument('-p', '--password',
                        required=True,
                        help='Specify the user password.')
    parser.add_argument('-t', '--timeout',
                        default=10,
                        type=int,
                        help='Specify the ssh timeout setting.')

    args = parser.parse_args()

    return (args.ssh_command, args.host, args.password, args.timeout)


def ssh_run(ssh_command, host, password, timeout):
    """
    Run specified ssh command, print output messages.
    """
    stdout_lines = []

    try:
        child = pexpect.spawn(ssh_command, timeout=timeout)
        expect_list = ['assword:', pexpect.EOF]
        index = child.expect(expect_list)

        if index == 0:
            child.sendline(password)
            stdout = child.read().strip()
        else:
            stdout = child.before

        stdout_lines = str(stdout, 'utf-8').split('\n')
    except Exception as warning:
        stdout_lines = ['*Warning*: Failed to ssh host "' + str(host) + '", ' + str(warning)]

    for line in stdout_lines:
        if line:
            print(line)


################
# Main Process #
################
def main():
    (ssh_command, host, password, timeout) = read_args()
    ssh_run(ssh_command, host, password, timeout)


if __name__ == '__main__':
    main()
