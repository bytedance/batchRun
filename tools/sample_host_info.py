# -*- coding: utf-8 -*-
################################
# File Name   : sample_host_info.py
# Author      : liyanqing.1987
# Created On  : 2024-08-12 18:34:15
# Description : Used to sample host os and hardware info.
################################
import os
import re
import sys
import json
import argparse

sys.path.insert(0, os.environ['BATCH_RUN_INSTALL_PATH'])
from common import common

os.environ['PYTHONUNBUFFERED'] = '1'
CWD = os.getcwd()


def read_args():
    """
    Read in arguments.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-H', '--hosts',
                        nargs='+',
                        default=[],
                        help='Specify the host(s) for batch_run.')
    parser.add_argument('-G', '--groups',
                        nargs='+',
                        default=[],
                        help='Specify host group(s) for batch_run.')
    parser.add_argument('-u', '--user',
                        default='',
                        help='Specify the user name when connectting host as.')
    parser.add_argument('-p', '--password',
                        default='',
                        help='Specify the user password when connectting host with.')
    parser.add_argument('-o', '--output_dir',
                        default=CWD,
                        help='Where to save temporary file and host_info.json, default is current directory.')

    args = parser.parse_args()

    # Check hosts/groups settings.
    if (not args.hosts) and (not args.groups):
        common.bprint('Neither of argument "--hosts" or "--groups" is specified.', level='Error')
        sys.exit(1)

    # Check output_dir.
    if not os.path.exists(args.output_dir):
        common.bprint('"' + str(args.output_dir) + '": No such directory.', level='Error')
        sys.exit(1)

    return args.hosts, args.groups, args.user, args.password, args.output_dir


class SampleHostInfo():
    def __init__(self, host_list, group_list, user, password, output_dir):
        self.output_dir = output_dir
        self.batch_run_command = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/bin/batch_run'

        if host_list:
            self.batch_run_command = str(self.batch_run_command) + ' -H ' + str(' '.join(host_list))

        if group_list:
            self.batch_run_command = str(self.batch_run_command) + ' -G ' + str(' '.join(group_list))

        if user:
            self.batch_run_command = str(self.batch_run_command) + ' -u ' + str(' '.join(user))

        if password:
            self.batch_run_command = str(self.batch_run_command) + ' -p ' + str(' '.join(password))

    def collect_host_info(self):
        """
        Collect host groups/os/hardware information from files under self.output_dir.
        """
        host_info_dic = {}

        # Get host group information.
        host_list_file = str(self.output_dir) + '/host_list.json'

        if os.path.exists(host_list_file):
            with open(host_list_file, 'r') as HLF:
                host_list_dic = json.loads(HLF.read())

        # Get host_info_dic based on *.info files.
        server_type_compile = re.compile(r'^\s*Hypervisor vendor:.*$')
        os_compile = re.compile(r'^\s*Description:\s*(.+?)\s*$')
        cpu_architecture_compile = re.compile(r'^\s*Architecture:\s*(\S+)\s*$')
        cpu_thread_compile = re.compile(r'^\s*CPU\(s\):\s*(\d+)\s*$')
        thread_per_core_compile = re.compile(r'^\s*Thread\(s\) per core:\s*(\d+)\s*$')
        cpu_model_compile = re.compile(r'^\s*Model name:\s*(.+?)\s*$')
        cpu_frequency_compile = re.compile(r'^\s*CPU MHz:\s*([0-9\.]+)\s*$')
        mem_size_compile = re.compile(r'^\s*Mem:\s*(\d+)\s+.*$')
        swap_size_compile = re.compile(r'^\s*Swap:\s*(\d+)\s+.*$')

        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if re.match(r'^(\S+)\.info$', file):
                    my_match = re.match(r'^(\S+)\.info$', file)
                    host = my_match.group(1)
                    host_info_dic.setdefault(host, {'groups': [],
                                                    'host_ip': [],
                                                    'host_name': [],
                                                    'server_type': 'physical',
                                                    'os': '',
                                                    'cpu_architecture': '',
                                                    'cpu_thread': 0,
                                                    'thread_per_core': 0,
                                                    'cpu_model': '',
                                                    'cpu_frequency': '',
                                                    'cpu_frequency_unit': 'GHz',
                                                    'mem_size': '',
                                                    'mem_size_unit': 'GB',
                                                    'swap_size': '',
                                                    'swap_size_unit': 'GB'})

                    if host in host_list_dic:
                        if 'groups' in host_list_dic[host]:
                            for groups in host_list_dic[host]['groups']:
                                if isinstance(groups, list):
                                    for group in groups:
                                        if group not in host_info_dic[host]['groups']:
                                            host_info_dic[host]['groups'].append(group)
                                else:
                                    if groups not in host_info_dic[host]['groups']:
                                        host_info_dic[host]['groups'].append(groups)

                        if 'host_ip' in host_list_dic[host]:
                            if len(host_list_dic[host]['host_ip']) == 1:
                                host_info_dic[host]['host_ip'] = host_list_dic[host]['host_ip'][0]
                            else:
                                host_info_dic[host]['host_ip'] = host_list_dic[host]['host_ip']
                        elif common.is_ip(host):
                            host_info_dic[host]['host_ip'] = host

                        if 'host_name' in host_list_dic[host]:
                            if len(host_list_dic[host]['host_name']) == 1:
                                host_info_dic[host]['host_name'] = host_list_dic[host]['host_name'][0]
                            else:
                                host_info_dic[host]['host_name'] = host_list_dic[host]['host_name']
                        elif not common.is_ip(host):
                            host_info_dic[host]['host_name'] = host

                    with open(os.path.join(root, file), 'r') as IF:
                        for line in IF.readlines():
                            if server_type_compile.match(line):
                                host_info_dic[host]['server_type'] = 'virtual'
                            elif os_compile.match(line):
                                my_match = os_compile.match(line)
                                host_info_dic[host]['os'] = my_match.group(1)
                            elif cpu_architecture_compile.match(line):
                                my_match = cpu_architecture_compile.match(line)
                                host_info_dic[host]['cpu_architecture'] = my_match.group(1)
                            elif cpu_thread_compile.match(line):
                                my_match = cpu_thread_compile.match(line)
                                host_info_dic[host]['cpu_thread'] = int(my_match.group(1))
                            elif thread_per_core_compile.match(line):
                                my_match = thread_per_core_compile.match(line)
                                host_info_dic[host]['thread_per_core'] = int(my_match.group(1))
                            elif cpu_model_compile.match(line):
                                my_match = cpu_model_compile.match(line)
                                host_info_dic[host]['cpu_model'] = my_match.group(1)
                            elif cpu_frequency_compile.match(line):
                                my_match = cpu_frequency_compile.match(line)
                                host_info_dic[host]['cpu_frequency'] = round(float(my_match.group(1))/1000, 2)
                            elif mem_size_compile.match(line):
                                my_match = mem_size_compile.match(line)
                                host_info_dic[host]['mem_size'] = int(my_match.group(1))
                            elif swap_size_compile.match(line):
                                my_match = swap_size_compile.match(line)
                                host_info_dic[host]['swap_size'] = int(my_match.group(1))

        return host_info_dic

    def sample_host_info(self):
        """
        Sample host os information with command "lsb_release -a".
        Sample host hardware information with command "lshw".
        Collect host information into "self.output_dir/host_info.json".
        """
        # Clean up self.output_dir.
        command = 'rm -rf *.info host_list.json host_info.json'
        common.bprint('>>> Clean up ' + str(self.output_dir) + ' ...')
        common.bprint(command, indent=4)
        os.chdir(self.output_dir)
        os.system(command)
        os.chdir(CWD)

        # Sample host list information.
        command = str(self.batch_run_command) + ' -L -o ' + str(self.output_dir) + '/host_list.json'
        common.bprint('>>> Sampling host list information ...')
        common.bprint(command, indent=4)
        os.system(command)

        # Sample host os/cpu/mem information.
        command = str(self.batch_run_command) + ' -c "lsb_release -a; lscpu; free -g" -P -l 1 -o ' + str(self.output_dir) + '/HOST.info'
        common.bprint('>>> Sampling host os/cpu/mem information ...')
        common.bprint(command, indent=4)
        os.system(command)

        # Collect host information.
        common.bprint('>>> Collecting host information ...')
        host_info_dic = self.collect_host_info()
        host_info_file = str(self.output_dir) + '/host_info.json'

        with open(host_info_file, 'w') as HIF:
            HIF.write(str(json.dumps(host_info_dic, ensure_ascii=False, indent=4)) + '\n')

        common.bprint('    Host info has been saved to file "' + str(host_info_file) + '".')


################
# Main Process #
################
def main():
    (hosts, groups, user, password, output_dir) = read_args()
    my_sample_host_info = SampleHostInfo(hosts, groups, user, password, output_dir)
    my_sample_host_info.sample_host_info()


if __name__ == '__main__':
    main()
