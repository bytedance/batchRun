# -*- coding: utf-8 -*-
################################
# File Name   : sample_host_queue.py
# Author      : liyanqing.1987
# Created On  : 2024-12-30 16:55:15
# Description : Used to sample host queue info.
################################
import os
import re
import sys
import json
import datetime
import argparse

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config

sys.path.insert(0, str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common
import common_lsf

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
                        help='Specify host(s) for batch_run.')
    parser.add_argument('-G', '--groups',
                        nargs='+',
                        default=[],
                        help='Specify host group(s) for batch_run.')
    parser.add_argument('-u', '--user',
                        default='',
                        help='Specify the user identity for SSH login to specified host.')
    parser.add_argument('-p', '--password',
                        default='',
                        help='Specify the user password for SSH login to specified host.')
    parser.add_argument('-P', '--parallel',
                        type=int,
                        default=0,
                        help='Specify the parallelism for batch_run, default is "0".')
    parser.add_argument('-t', '--timeout',
                        type=int,
                        default=20,
                        help='Specify the timeout for batch_run, default is "20".')
    parser.add_argument('-i', '--host_info_json',
                        default=str(config.db_path) + '/host_info/host_info.json',
                        help='Specify host info file to collect host static information, default is "' + str(config.db_path) + '/host_info/host_info.json".')
    parser.add_argument('-o', '--output_dir',
                        default=str(config.db_path) + '/host_queue',
                        help='Specify host info output directory, default is "' + str(config.db_path) + '/host_queue".')

    args = parser.parse_args()

    # Check and update output_dir.
    if os.path.exists(args.output_dir):
        args.output_dir = os.path.realpath(args.output_dir)
    else:
        common.bprint('"' + str(args.output_dir) + '": No such directory.', level='Error')
        sys.exit(1)

    return args.hosts, args.groups, args.user, args.password, args.parallel, args.timeout, args.host_info_json, args.output_dir


class SampleHostQueue():
    def __init__(self, host_list, group_list, user, password, parallel, timeout, host_info_json, output_dir):
        self.host_list = host_list
        self.group_list = group_list
        self.user = user
        self.password = password
        self.parallel = parallel
        self.timeout = timeout
        self.output_dir = output_dir
        self.latest_host_queue_file = str(self.output_dir) + '/host_queue.json'
        current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_host_queue_file = str(self.output_dir) + '/host_queue.json.' + str(current_time)
        self.host_info_dic = self.parse_host_info_json(host_info_json)

    def parse_host_info_json(self, host_info_json):
        host_info_dic = {}

        if os.path.exists(host_info_json):
            with open(host_info_json, 'r') as HIJ:
                host_info_dic = json.loads(HIJ.read())

        return host_info_dic

    def cleanup_with_suffix(self, suffix_list=['lsid', 'queues', 'hosts', 'bmgroup']):
        common.bprint('\n>>> Cleaning up files with suffixs "' + '|'.join(suffix_list) + '" ...')

        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                for suffix in suffix_list:
                    if file.endswith(suffix):
                        file_path = os.path.join(root, file)
                        os.remove(file_path)

    def get_batch_run_command(self, host_list=[], group_list=[], user='', password='', parallel=0, timeout=20):
        """
        Get default batch_run command (without run command).
        """
        batch_run_command = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/bin/batch_run'

        if host_list:
            batch_run_command = str(batch_run_command) + ' --hosts ' + str(' '.join(host_list))

        if group_list:
            batch_run_command = str(batch_run_command) + ' --groups ' + str(' '.join(group_list))

        if user:
            batch_run_command = str(batch_run_command) + ' --user ' + str(user)

        if password:
            batch_run_command = str(batch_run_command) + ' --password ' + str(password)

        batch_run_command = str(batch_run_command) + ' --parallel ' + str(parallel)

        if timeout:
            batch_run_command = str(batch_run_command) + ' --timeout ' + str(timeout)

        return batch_run_command

    def sample_host_lsid_info(self, host_list, group_list):
        """
        Sample host lsid info with command "lsid".
        """
        common.bprint('\n>>> Sampling host lsid information ...')
        sample_command = 'source /etc/profile; lsid'
        batch_run_command = self.get_batch_run_command(host_list, group_list, self.user, self.password, self.parallel, self.timeout)
        command = str(batch_run_command) + ' --command "' + str(sample_command) + '" --output_message_level 1 --output_file ' + str(self.output_dir) + '/HOST.lsid'
        common.bprint(command, indent=4)
        os.system(command)

    def collect_host_lsid_info(self):
        """
        Collect host lsid info with function common_lsf.get_lsid_info().
        Return cluster_host_dic: scheduler -> cluster -> host_ip.
        Return host_lsid_dic: host_ip -> scheduler/version/cluster/master.
        """
        common.bprint('\n>>> Collecting host lsid information ...')
        cluster_host_dic = {}
        host_lsid_dic = {}

        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if re.match(r'^(\S+)\.lsid$', file):
                    my_match = re.match(r'^(\S+)\.lsid$', file)
                    host_ip = my_match.group(1)
                    host_lsid_dic[host_ip] = {'scheduler': '', 'version': '', 'cluster': '', 'master': ''}
                    file_path = os.path.join(root, file)
                    (tool, tool_version, cluster, master) = common_lsf.get_lsid_info(command='cat ' + str(file_path))

                    if tool:
                        host_lsid_dic[host_ip] = {'scheduler': tool, 'version': tool_version, 'cluster': cluster, 'master': master}
                        cluster_host_dic.setdefault(tool, {})
                        cluster_host_dic[tool].setdefault(cluster, [])
                        cluster_host_dic[tool][cluster].append(host_ip)

        return cluster_host_dic, host_lsid_dic

    def sample_cluster_host_info(self, cluster_host_dic):
        """
        Sample queue-host relationship with command "bqueues/bhosts/bmgroup".
        """
        common.bprint('\n>>> Sampling cluster host information ...')

        for scheduler in cluster_host_dic.keys():
            for cluster in cluster_host_dic[scheduler].keys():
                first_host = cluster_host_dic[scheduler][cluster][0]

                common.bprint('* Sampling queues information for scheduler "' + str(scheduler) + '" cluster "' + str(cluster) + '" on host "' + str(first_host) + '" ...', indent=4)
                sample_command = 'source /etc/profile; bqueues -l'
                batch_run_command = self.get_batch_run_command([first_host], [], self.user, self.password, 1, self.timeout)
                cluster_queues_file = str(self.output_dir) + '/' + str(scheduler) + '_' + str(cluster) + '.bqueues'
                command = str(batch_run_command) + ' --command "' + str(sample_command) + '" --output_message_level 1 --output_file ' + str(cluster_queues_file)
                common.bprint(command, indent=4)
                os.system(command)

                common.bprint('* Sampling hosts information for scheduler "' + str(scheduler) + '" cluster "' + str(cluster) + '" on host "' + str(first_host) + '" ...', indent=4)
                sample_command = 'source /etc/profile; bhosts -w'
                batch_run_command = self.get_batch_run_command([first_host], [], self.user, self.password, 1, self.timeout)
                cluster_hosts_file = str(self.output_dir) + '/' + str(scheduler) + '_' + str(cluster) + '.bhosts'
                command = str(batch_run_command) + ' --command "' + str(sample_command) + '" --output_message_level 1 --output_file ' + str(cluster_hosts_file)
                common.bprint(command, indent=4)
                os.system(command)

                common.bprint('* Sampling host group information for scheduler "' + str(scheduler) + '" cluster "' + str(cluster) + '" on host "' + str(first_host) + '" ...', indent=4)
                sample_command = 'source /etc/profile; bmgroup -w -r'
                batch_run_command = self.get_batch_run_command([first_host], [], self.user, self.password, 1, self.timeout)
                cluster_bmgroup_file = str(self.output_dir) + '/' + str(scheduler) + '_' + str(cluster) + '.bmgroup'
                command = str(batch_run_command) + ' --command "' + str(sample_command) + '" --output_message_level 1 --output_file ' + str(cluster_bmgroup_file)
                common.bprint(command, indent=4)
                os.system(command)

    def collect_host_queue_info(self, host_lsid_dic):
        """
        Collect queue-host relationship with function common_lsf.get_queue_host_info().
        Return host_queue_dic: host_ip -> scheduler/version/cluster/queue_list.
        """
        common.bprint('\n>>> Collecting host cheduler/cluster/queue information ...')

        # Initalize host_queue_dic.
        host_queue_dic = {}

        for host_ip in host_lsid_dic.keys():
            host_queue_dic.setdefault(host_ip, {'scheduler': '', 'cluster': '', 'queues': ''})

        # Collect tmp host queue info with tmp_dic.
        tmp_dic = {}

        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if re.match(r'^(\S+)\.bqueues$', file):
                    my_match = re.match(r'^(\S+)\.bqueues$', file)
                    host_ip = my_match.group(1)
                    file_path = os.path.join(root, file)
                    tmp_dic.setdefault(host_ip, {})
                    tmp_dic[host_ip].setdefault('bqueues_file', file_path)
                elif re.match(r'^(\S+)\.bhosts$', file):
                    my_match = re.match(r'^(\S+)\.bhosts$', file)
                    host_ip = my_match.group(1)
                    file_path = os.path.join(root, file)
                    tmp_dic.setdefault(host_ip, {})
                    tmp_dic[host_ip].setdefault('bhosts_file', file_path)
                elif re.match(r'^(\S+)\.bmgroup$', file):
                    my_match = re.match(r'^(\S+)\.bmgroup$', file)
                    host_ip = my_match.group(1)
                    file_path = os.path.join(root, file)
                    tmp_dic.setdefault(host_ip, {})
                    tmp_dic[host_ip].setdefault('bmgroup_file', file_path)

        # lsf_host_queue_dic: host <-> queues.
        # self.host_info_dic: host_ip <-> host_name.
        # host_lsid_dic: host <-> scheduler/version/cluster/master.
        for host_ip in tmp_dic.keys():
            if ('bqueues_file' in tmp_dic[host_ip]) and ('bhosts_file' in tmp_dic[host_ip]) and ('bmgroup_file' in tmp_dic[host_ip]):
                lsf_host_queue_dic = common_lsf.get_host_queue_info(command='cat ' + str(tmp_dic[host_ip]['bqueues_file']), get_hosts_list_command='cat ' + str(tmp_dic[host_ip]['bhosts_file']), get_bmgroup_info_command='cat ' + str(tmp_dic[host_ip]['bmgroup_file']))

                if lsf_host_queue_dic:
                    for host in self.host_info_dic.keys():
                        if (host in host_lsid_dic) and ('host_name' in self.host_info_dic[host]):
                            for host_name in self.host_info_dic[host]['host_name']:
                                if host_name in lsf_host_queue_dic.keys():
                                    host_queue_dic[host] = {'scheduler': str(host_lsid_dic[host]['scheduler']) + '_' + str(host_lsid_dic[host]['version']), 'cluster': host_lsid_dic[host]['cluster'], 'queues': lsf_host_queue_dic[host_name]}

        return host_queue_dic

    def write_host_queue_file(self, host_queue_dic):
        common.bprint('\n>>> Write host scheduler/cluster/queue relationship file ...')

        with open(self.current_host_queue_file, 'w') as HQF:
            HQF.write(str(json.dumps(host_queue_dic, ensure_ascii=False, indent=4)) + '\n')

        common.bprint('Host queue info has been saved to file "' + str(self.current_host_queue_file) + '".', indent=4)

    def link_host_queue_file(self):
        common.bprint('\n>>> Link current host queue file into host_queue.json')
        common.bprint('ln -s ' + str(self.current_host_queue_file) + ' ' + str(self.latest_host_queue_file), indent=4)

        if os.path.exists(self.latest_host_queue_file):
            try:
                os.remove(self.latest_host_queue_file)
            except Exception as error:
                common.bprint('Failed on removing ' + str(self.latest_host_queue_file) + '": ' + str(error), indent=4, level='Error')
                sys.exit(1)

        try:
            os.symlink(self.current_host_queue_file, self.latest_host_queue_file)
        except Exception as error:
            common.bprint('Failed on Linking "' + str(self.current_host_queue_file) + '" into "' + str(self.latest_host_queue_file) + '": ' + str(error), indent=4, level='Error')
            sys.exit(1)

    def sample_host_queue(self):
        # Cleanup self.output_dir.
        self.cleanup_with_suffix()

        # Sample host lsid info.
        self.sample_host_lsid_info(self.host_list, self.group_list)

        # Collect host lsid info.
        (cluster_host_dic, host_lsid_dic) = self.collect_host_lsid_info()
        self.cleanup_with_suffix(suffix_list=['lsid', ])

        # Sample cluster host info.
        self.sample_cluster_host_info(cluster_host_dic)

        # Collect cluster host info.
        host_queue_dic = self.collect_host_queue_info(host_lsid_dic)
        self.cleanup_with_suffix(suffix_list=['queues', 'hosts', 'bmgroup'])

        # Write self.current_host_queue_file with host_queue_dic.
        self.write_host_queue_file(host_queue_dic)

        # Link self.current_host_queue_file into self.latest_host_queue_file.
        self.link_host_queue_file()


################
# Main Process #
################
def main():
    (hosts, groups, user, password, parallel, timeout, host_info_json, output_dir) = read_args()
    my_sample_host_queue = SampleHostQueue(hosts, groups, user, password, parallel, timeout, host_info_json, output_dir)
    my_sample_host_queue.sample_host_queue()


if __name__ == '__main__':
    main()
