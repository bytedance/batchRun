#!/bin/env python3
# -*- coding: utf-8 -*-
################################
# File Name   : batch_run.py
# Author      : liyanqing
# Created On  : 2021-08-09 19:18:43
# Description : Run command on multi-hosts, just like pssh or ansible.
################################
import os
import re
import sys
import getpass
import datetime
import argparse
import threading

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common
import common_password

os.environ['PYTHONUNBUFFERED'] = '1'
REAL_USER = getpass.getuser()
CURRENT_USER = os.popen('whoami').read().strip()
CURRENT_TIME = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')


def read_args(host_list_class):
    """
    Read in arguments.
    """
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-H', '--hosts',
                        nargs='+',
                        default=[],
                        help='''Specify the host(s), could be host_ip or host_name, format is "host" or "host:port".
"ALL" means all hosts on ''' + str(config.HOST_LIST) + '''.
"~<HOST>" means exclud the specified host.''')
    parser.add_argument('-G', '--host_groups',
                        nargs='+',
                        default=[],
                        help='Specify host group(s) which are on ' + str(config.HOST_LIST) + '''.
"ALL" means all groups on ''' + str(config.HOST_LIST) + '''.
"~<GROUP>" means exclud the specified group.''')
    parser.add_argument('-P', '--parallel',
                        action='store_true',
                        default=False,
                        help='Run command parallel on specified host(s), default is in serial.')
    parser.add_argument('-u', '--user',
                        default=CURRENT_USER,
                        help='Specify the user name when connectting host as.')
    parser.add_argument('-p', '--password',
                        default='',
                        help='Specify the user password when connectting host with.')
    parser.add_argument('-c', '--command',
                        nargs='+',
                        default=[],
                        help='Specify command you want run on specified host(s).')
    parser.add_argument('-m', '--multi_commands_file',
                        default='',
                        help='Specify a script with multi commands, will execute line by line.')
    parser.add_argument('-t', '--timeout',
                        type=int,
                        default=config.TIMEOUT,
                        help='Specify ssh command timeout, default is 10 seconds.')
    parser.add_argument('-o', '--output_message_level',
                        type=int,
                        choices=[0, 1, 2, 3, 4],
                        default=3,
                        help='''Specify output message level, default is "3".
"0" means silence;
"1" only show host info;
"2" only show one line output message;
"3" show normal output message;
"4" show verbose output message.''')
    parser.add_argument('--list_hosts',
                        nargs='+',
                        default=[],
                        help='List all or specified-group hosts on ' + str(config.HOST_LIST) + '''.
"all" or "ALL" means all hosts on host list file.
"<group>" means hosts on specified groups.''')

    args = parser.parse_args()

    # List hosts
    if args.list_hosts:
        list_hosts(host_list_class, args.list_hosts)

    # Get hosts.
    specified_host_dic = get_specified_hosts(host_list_class, args.hosts, args.host_groups)

    # Get password.
    args.password = get_user_password(args.user, args.password)

    # Get commands.
    commands = get_command_info(args.command, args.multi_commands_file)

    # Set output_message_level for parallel mode.
    if args.parallel and (args.output_message_level == 3):
        args.output_message_level = 1

    return(specified_host_dic, args.parallel, args.user, args.password, commands, args.timeout, args.output_message_level)


def list_hosts(host_list_class, show_group_list):
    for (group, group_dic) in host_list_class.host_list_dic.items():
        if ('all' in show_group_list) or ('ALL' in show_group_list) or (group in show_group_list):
            print('GROUP : ' + str(group))

            # Show hosts info.
            if 'hosts' in group_dic:
                for host_ip in group_dic['hosts'].keys():
                    if 'host_name' in group_dic['hosts'][host_ip]:
                        host_name = group_dic['hosts'][host_ip]['host_name']
                    else:
                        host_name = ''

                    if 'ssh_port' in group_dic['hosts'][host_ip]:
                        ssh_port = group_dic['hosts'][host_ip]['ssh_port']
                    else:
                        ssh_port = ''

                    print('      %-15s    %s    %s' % (host_ip, host_name, ssh_port))

            # Show sub_groups info.
            if 'sub_groups' in group_dic:
                for sub_group in group_dic['sub_groups']:
                    print('      ' + str(sub_group) + '/')

    sys.exit(0)


def get_specified_hosts(host_list_class, specified_host_list, specified_host_group_list):
    specified_host_dic = {}

    if specified_host_list or specified_host_group_list:
        excluded_host_list = []

        # If host_groups is specified, parse and save.
        if specified_host_group_list:
            if 'ALL' in specified_host_group_list:
                specified_host_group_list.remove('ALL')

                for group in host_list_class.group_list:
                    if group not in specified_host_group_list:
                        specified_host_group_list.append(group)

            (specified_host_dic, excluded_host_list) = common.parse_specified_groups(specified_host_group_list, host_list_class, excluded_host_list)

        # If hosts is specified, parse and save.
        if specified_host_list:
            if 'ALL' in specified_host_list:
                specified_host_list.remove('ALL')

                for host in host_list_class.host_ip_dic.keys():
                    if host not in specified_host_list:
                        specified_host_list.append(host)

            (host_dic, excluded_host_list) = common.parse_specified_hosts(specified_host_list, host_list_class, excluded_host_list)

            for host in host_dic.keys():
                if host in specified_host_dic:
                    # Host (host_ip) is repeated.
                    common.print_warning('*Waring*: host "' + str(host) + '" is specified repeatedly.')
                    continue
                else:
                    # Host (host_name) is repeated.
                    continue_mark = False

                    for host_ip in specified_host_dic.keys():
                        if ('host_name' in specified_host_dic[host_ip]) and (specified_host_dic[host_ip]['host_name'] == host):
                            common.print_warning('*Waring*: host "' + str(host) + '(' + str(host_ip) + ')" is specified repeatedly.')
                            continue_mark = True
                            break

                    if continue_mark:
                        continue

                specified_host_dic[host] = host_dic[host]

        # Remove excluded hosts.
        remove_host_list = []

        for host in specified_host_dic.keys():
            if (host in excluded_host_list) or (('host_name' in specified_host_dic[host]) and (specified_host_dic[host]['host_name'] in excluded_host_list)):
                remove_host_list.append(host)

        for host in remove_host_list:
            del specified_host_dic[host]

    # specified_host_dic cannot be empty.
    if not specified_host_dic:
        common.print_warning('*Warning*: No valid host or host group is specified.')

    return(specified_host_dic)


def get_user_password(user, password):
    if not password:
        password = common_password.get_password(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config/password.encrypted', user)

        if not password:
            common.print_warning('*Warning*: user password is not specified!')

    return(password)


def get_command_info(command, multi_commands_file):
    commands = []
    default_script_dir = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/scripts'

    if not multi_commands_file:
        # Try to find command on batchRun default scripts directory.
        if command:
            for (root, dirs, files) in os.walk(default_script_dir):
                if command[0] in files:
                    command[0] = str(root) + '/' + str(command[0])
                    break

            command_string = ' '.join(command)
            commands.append(command_string)
    else:
        if not os.path.exists(multi_commands_file):
            # Try to find multi_commands_file on batchRun default scripts directory.
            find_mark = False

            for (root, dirs, files) in os.walk(default_script_dir):
                if multi_commands_file in files:
                    multi_commands_file = str(root) + '/' + str(multi_commands_file)
                    find_mark = True
                    break

            if not find_mark:
                common.print_error('*Error*: ' + str(multi_commands_file) + ': No such multi_command file!')
                sys.exit(1)

        with open(multi_commands_file, 'r') as MC:
            for line in MC.readlines():
                if re.match('^\s*$', line) or re.match('^\s*#.*$', line):
                    continue
                else:
                    commands.append(line.strip())

    # Make sure at least one valid command is specified.
    if not commands:
        common.print_error('*Error*: No valid command is specified!')
        sys.exit(1)

    return(commands)


class BatchRun():
    def __init__(self, specified_host_dic, parallel, user, password, commands, timeout, output_message_level):
        self.specified_host_dic = specified_host_dic
        self.parallel = parallel
        self.user = user
        self.password = password
        self.commands = commands
        self.timeout = timeout
        self.output_message_level = output_message_level

    def save_log(self, message, output_message_level_list=[0, 1, 2, 3, 4], nowrap=False):
        # Save log.
        if not config.LOG_DIR:
            common.print_warning('*Warning*: Please set "LOG_DIR" first on "' + str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config/config.py".')
        else:
            if not os.path.exists(config.LOG_DIR):
                common.print_warning('*Warning*: "' + str(config.LOG_DIR) + ': No such log directory.')
            else:
                log_file = str(config.LOG_DIR) + '/' + str(CURRENT_USER) + '_' + str(CURRENT_TIME) + '.log'

                if not os.path.exists(log_file):
                    with open(log_file, 'a') as LF:
                        LF.write('Real    User : ' + str(REAL_USER) + '\n')
                        LF.write('Current User : ' + str(CURRENT_USER) + '\n')
                        LF.write('Current Time : ' + str(CURRENT_TIME) + '\n')
                        LF.write('\n')

                with open(log_file, 'a') as LF:
                    LF.write(str(message) + '\n')

        # Print message.
        if self.output_message_level in output_message_level_list:
            if nowrap:
                print(message, end=' ')
            else:
                print(message)

    def get_ssh_command(self, host):
        # Default ssh setting.
        if config.DEFAULT_SSH_COMMAND:
            ssh_command = config.DEFAULT_SSH_COMMAND
        else:
            ssh_command = 'ssh -o StrictHostKeyChecking=no'

        if 'ssh_port' in self.specified_host_dic[host]:
            ssh_command = str(ssh_command) + ' -p ' + str(self.specified_host_dic[host]['ssh_port'])

        if ('host_ip' in self.specified_host_dic[host]) and (self.specified_host_dic[host]['host_ip'] != host):
            host = self.specified_host_dic[host]['host_ip']

        # Add user setting.
        if self.user:
            ssh_command = str(ssh_command) + ' ' + str(self.user) + '@' + str(host)
        else:
            ssh_command = str(ssh_command) + ' ' + str(host)

        return(ssh_command)

    def execute_ssh_command(self, host):
        # Save log
        self.save_log('', [3, 4])

        if self.output_message_level == 2:
            self.save_log('>>> ' + str(host), [2, ], nowrap=True)
        elif self.output_message_level in [1, 3, 4]:
            self.save_log('>>> ' + str(host), [1, 3, 4])

        # Get original ssh command.
        for (i, command) in enumerate(self.commands):
            ssh_command = self.get_ssh_command(host)
            ssh_command = str(ssh_command) + ' ' + str(command)
            ssh_command = re.sub("'", "\\'", ssh_command)
            ssh_command = re.sub('"', '\\"', ssh_command)

            if i != 0:
                self.save_log('', [4, ])

            # Execute ssh and input password.
            run_ssh_command = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/tools/run_ssh_command.py -c "' + str(ssh_command) + '" -H ' + str(host) + ' -p ' + str(self.password) + ' -t ' + str(self.timeout)
            encrypted_run_ssh_command = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/tools/run_ssh_command.py -c "' + str(ssh_command) + '" -H ' + str(host) + ' -p *** -t ' + str(self.timeout)
            self.save_log('    ' + str(encrypted_run_ssh_command), [4, ])
            (return_code, stdout, stderr) = common.run_command(run_ssh_command)
            stdout_lines = str(stdout, 'utf-8').split('\n')

            # Print command output message as expected method.
            if stdout_lines == ['']:
                self.save_log('')
            else:
                self.save_log('    ==== output ====', [4, ])

                for stdout_line in stdout_lines:
                    if stdout_line:
                        self.save_log('    ' + str(stdout_line), [2, 3, 4])

                        if self.output_message_level == 2:
                            break

                self.save_log('    ================', [4, ])

    def run(self):
        if self.parallel:
            thread_list = []

            for host in self.specified_host_dic.keys():
                thread = threading.Thread(target=self.execute_ssh_command, args=(host, ))
                thread.start()
                thread_list.append(thread)

            # Join sub-threads with main-thread.
            for thread in thread_list:
                thread.join()
        else:
            for host in self.specified_host_dic.keys():
                self.execute_ssh_command(host)


################
# Main Process #
################
def main():
    host_list_class = common.ParseHostList()
    (specified_host_dic, parallel, user, password, commands, timeout, output_message_level) = read_args(host_list_class)
    my_batch_run = BatchRun(specified_host_dic, parallel, user, password, commands, timeout, output_message_level)
    my_batch_run.run()


if __name__ == '__main__':
    main()
