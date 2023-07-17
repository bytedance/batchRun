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
    # Switch input_host into real host_list.
    if input_port:
        (specified_host_dic, excluded_host_list) = common.parse_specified_hosts([str(input_host) + ':' + str(input_port),])
    else:
        (specified_host_dic, excluded_host_list) = common.parse_specified_hosts([input_host,])

    host_list = []

    for specified_host in specified_host_dic.keys():
        if 'host_ip' in specified_host_dic[specified_host].keys():
            for host_ip in specified_host_dic[specified_host]['host_ip']:
                if host_ip not in host_list:
                    host_list.append(host_ip)
        else:
            host_list.append(specified_host)

    # Save expected host&port into valid_host and valid_port.
    valid_host = input_host
    valid_port = input_port

    if len(host_list) == 1:
        valid_host = host_list[0]
    elif len(host_list) > 1:
        # If more than one possible host, choice one.
        print('')
        print('Below are possible hosts:')

        for (i, host) in enumerate(host_list):
            print('  [' + str(i) + '] ' + str(host))

        print('  [' + str(len(host_list)) + '] None of above hosts')
        print('')

        host_num = input('Please choice one (number): ')
        host_num = int(host_num)

        if host_num in range(len(host_list)):
            valid_host = host_list[host_num]

    if not input_port:
        if valid_host in specified_host_dic.keys():
            if 'ssh_port' in specified_host_dic[valid_host].keys():
                valid_port = specified_host_dic[valid_host]['ssh_port']
        else:
            for specified_host in specified_host_dic.keys():
                if ('host_ip' in specified_host_dic[specified_host].keys()) and ('ssh_port' in specified_host_dic[specified_host].keys()):
                    for (i, host_ip) in enumerate(specified_host_dic[specified_host]['host_ip']):
                        if valid_host == host_ip:
                            ssh_port = specified_host_dic[specified_host]['ssh_port'][i]

                            if ssh_port:
                                valid_port = ssh_port

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
