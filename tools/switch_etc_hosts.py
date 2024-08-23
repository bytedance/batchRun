# -*- coding: utf-8 -*-
################################
# File Name   : switch_etc_hosts.py
# Author      : liyanqing.1987
# Created On  : 2023-07-14 15:12:43
# Description :
################################
import os
import re
import sys
import argparse

os.environ['PYTHONUNBUFFERED'] = '1'


def read_args():
    """
    Read in arguments.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-e', '--expected_ips',
                        nargs='+',
                        default=[],
                        help='Specify expected ip(s), support regular expressions.')
    parser.add_argument('-E', '--excluded_ips',
                        nargs='+',
                        default=[],
                        help='Specify excluded ip(s), support regular expressions.')
    parser.add_argument('-i', '--input_file',
                        default='/etc/hosts',
                        help='Specify input file, default is "/etc/hosts".')
    parser.add_argument('-o', '--output_file',
                        default='./host.list',
                        help='Specify output file, default is "./host.list".')
    parser.add_argument('-a', '--append',
                        default='',
                        help='Append configuration file into output file.')
    parser.add_argument('-r', '--rewrite',
                        action='store_true',
                        default=False,
                        help='Rewrite mode, rewrite output file by force.')
    parser.add_argument('-t', '--tool',
                        default='batchRun',
                        choices=['batchRun', 'ansible'],
                        help='Which tool the host list is for, default is "batchRun".')

    args = parser.parse_args()

    # input_file must exists.
    if not os.path.exists(args.input_file):
        print('*Error*: "' + str(args.input_file) + '": No such input file.')
        sys.exit(1)

    # Will exit if output_file exists without rewrite mode.
    if os.path.exists(args.output_file) and (not args.rewrite):
        print('*Error*: Output file "' + str(args.output_file) + '" exists, please remote it, or enable rewrite mode.')
        sys.exit(1)

    # Check append file exists or not.
    if args.append and (not os.path.exists(args.append)):
        args.append = ''

    return (args.expected_ips, args.excluded_ips, args.input_file, args.output_file, args.append, args.tool)


class SwitchEtcHosts():
    """
    Switch /etc/hosts (or similar) file into batchRun host.list file.
    """
    def __init__(self, expected_ip_list, excluded_ip_list, input_file, output_file, append_file, tool):
        self.expected_ip_list = expected_ip_list
        self.excluded_ip_list = excluded_ip_list
        self.input_file = input_file
        self.output_file = output_file
        self.append_file = append_file
        self.tool = tool

    def parse_input_file(self):
        """
        input_file must match below format.
        # GROUP : <group>
        <host_ip> <host_names>
        <host_ip> <host_names> # SSH_PORT=<port>
        """
        input_dic = {}
        group = ''

        with open(self.input_file, 'r') as IF:
            for line in IF.readlines():
                line = line.strip()

                if re.match(r'^\s*$', line):
                    continue
                elif re.match(r'^\s*#.*$', line):
                    if re.match(r'^\s*#\s*GROUP\s*:\s*(\S+).*$', line):
                        my_match = re.match(r'^\s*#\s*GROUP\s*:\s*(\S+).*$', line)
                        group = my_match.group(1)

                        if group in input_dic:
                            print('*Error*: Group "' + str(group) + '" is defined repeatedly.')
                            sys.exit(1)
                        else:
                            input_dic[group] = {}
                    else:
                        print('*Warning*: Comment line, igonre')
                        print('           ' + str(line))
                elif re.match(r'^\s*((([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5]))\s+(.+?)\s*(#.*?)?\s*$', line):
                    my_match = re.match(r'^\s*((([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5]))\s+(.+?)\s*(#.*?)?\s*$', line)
                    host_ip = my_match.group(1)
                    host_names_string = my_match.group(5)
                    comment_string = my_match.group(6)
                    ssh_port = ''

                    if comment_string and re.match(r'^#\s*SSH_PORT\s*=\s*(\d+)$', comment_string):
                        my_match = re.match(r'^#\s*SSH_PORT\s*=\s*(\d+)$', comment_string)
                        ssh_port = my_match.group(1)

                    if not group:
                        print('*Warning*: Group missing for below line, igonre')
                        print('           ' + str(line))
                    else:
                        # Filter excluded ip(s).
                        if self.excluded_ip_list:
                            continue_mark = False

                            for excluded_ip in self.excluded_ip_list:
                                if (host_ip == excluded_ip) or re.match(excluded_ip, host_ip):
                                    continue_mark = True
                                    break

                            if continue_mark:
                                continue

                        # Filter expected ip(s).
                        if self.expected_ip_list:
                            continue_mark = True

                            for expected_ip in self.expected_ip_list:
                                if (host_ip == expected_ip) or re.match(expected_ip, host_ip):
                                    continue_mark = False
                                    break

                            if continue_mark:
                                continue

                        # Save host_ip into input_dic.
                        input_dic[group].setdefault(host_ip, {})
                        input_dic[group][host_ip].setdefault('host_name', [])

                        for host_name in host_names_string.split():
                            if host_name not in input_dic[group][host_ip]['host_name']:
                                input_dic[group][host_ip]['host_name'].append(host_name)

                        if ssh_port:
                            input_dic[group][host_ip].setdefault('ssh_port', ssh_port)
                else:
                    print('*Warning*: Meaningless line, igonre')
                    print('           ' + str(line))

        return input_dic

    def write_output_file(self, input_dic):
        """
        Write output_file as batchRun host.list format.
        """
        if input_dic:
            with open(self.output_file, 'w') as OF:
                for group in input_dic.keys():
                    if input_dic[group]:
                        OF.write('\n[' + str(group) + ']\n')

                        for host_ip in input_dic[group].keys():
                            for host_name in input_dic[group][host_ip]['host_name']:
                                if self.tool == 'batchRun':
                                    if 'ssh_port' in input_dic[group][host_ip]:
                                        OF.write(str(host_ip) + '  ssh_host=' + str(host_name) + '  ssh_port=' + str(input_dic[group][host_ip]['ssh_port']) + '\n')
                                    else:
                                        OF.write(str(host_ip) + '  ssh_host=' + str(host_name) + '\n')
                                elif self.tool == 'ansible':
                                    if 'ssh_port' in input_dic[group][host_ip]:
                                        OF.write(str(host_ip) + '  ansible_ssh_host=' + str(host_name) + '  ansible_ssh_port=' + str(input_dic[group][host_ip]['ssh_port']) + '\n')
                                    else:
                                        OF.write(str(host_ip) + '  ansible_ssh_host=' + str(host_name) + '\n')

                if self.append_file:
                    with open(self.append_file, 'r') as AF:
                        for line in AF.readlines():
                            OF.write(str(line).strip() + '\n')

            print('')
            print('Output File : ' + str(self.output_file))

    def run(self):
        input_dic = self.parse_input_file()
        self.write_output_file(input_dic)


################
# Main Process #
################
def main():
    (expected_ip_list, excluded_ip_list, input_file, output_file, append_file, tool) = read_args()
    my_switch_etc_hosts = SwitchEtcHosts(expected_ip_list, excluded_ip_list, input_file, output_file, append_file, tool)
    my_switch_etc_hosts.run()


if __name__ == '__main__':
    main()
