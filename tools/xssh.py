#!/bin/env python3
# -*- coding: utf-8 -*-
################################
# File Name   : xssh.py
# Author      : liyanqing
# Created On  : 2021-08-21 00:00:00
# Description :
################################
import os
import sys

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common

os.environ['PYTHONUNBUFFERED'] = '1'


def arg_parse():
    host = ''
    port = ''

    if len(sys.argv) == 2:
        if (sys.argv[1] == '-h') or (sys.argv[1] == '-help') or (sys.argv[1] == '--help') or (sys.argv[1] == 'help'):
            print('Usage: xssh host <port>')
            sys.exit(0)
        else:
            host = sys.argv[1]
    elif len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        print('Usage: xssh host <port>')
        sys.exit(1)

    return (host, port)


def get_valid_host_and_port(input_host, input_port):
    valid_host_dic = {}
    (specified_host_dic, excluded_host_list) = common.parse_specified_hosts([input_host, ])
    host_list = list(specified_host_dic.keys())

    if len(host_list) == 1:
        valid_host_dic = specified_host_dic[host_list[0]]
    elif len(host_list) > 1:
        # If more than one possible host, choice one.
        print('Below are possible hosts:')

        for (i, host) in enumerate(host_list):
            print('  [' + str(i) + '] ' + str(host))

        print('  [' + str(len(host_list)) + '] None of above hosts')
        print('')

        host_num = input('Please choice one (number): ')
        host_num = int(host_num)

        if host_num in range(len(host_list)):
            valid_host_dic = specified_host_dic[host_list[host_num]]
        else:
            valid_host_dic = {'host_name': input_host}

    # Get valid host and valid port.
    valid_host = input_host
    valid_port = input_port

    if 'host_ip' in valid_host_dic.keys():
        valid_host = valid_host_dic['host_ip']
    elif 'host_name' in valid_host_dic:
        valid_host = valid_host_dic['host_name']

    if 'ssh_port' in valid_host_dic.keys():
        if valid_port:
            if valid_host_dic['ssh_port'] != valid_port:
                common.print_error('*Error*: For host "' + str(valid_host) + '", specified ssh_port "' + str(valid_port) + '" is different with configured ssh_port "' + str(valid_host_dic['ssh_port']) + '".')
                sys.exit(1)
        else:
            valid_port = valid_host_dic['ssh_port']

    if not valid_port:
        valid_port = 22

    return (valid_host, valid_port)


def execute_ssh(host, port):
    command = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/tools/essh ' + str(host) + ' ' + str(port)
    xterm_command = 'xterm -e "' + str(command) + '" &'

    print(xterm_command)

    os.system(xterm_command)


################
# Main Process #
################
def main():
    (host, port) = arg_parse()
    (host, port) = get_valid_host_and_port(host, port)
    execute_ssh(host, port)


if __name__ == '__main__':
    main()
