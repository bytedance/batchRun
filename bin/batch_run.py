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
import copy
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
                        help='''Specify the host(s), could be below format:
<host_ip>
<host_ip>:<ssh_port>
<host_name>
<host_name>:<ssh_port>
~<host_ip>
~<host_name>

"ALL" means all hosts on ''' + str(config.HOST_LIST) + '''.
"~<host>" means exclud specified host.''')
    parser.add_argument('-G', '--groups',
                        nargs='+',
                        default=[],
                        help='Specify host group(s) which are on ' + str(config.HOST_LIST) + '''.
Could be below format:
<GROUP>
~<GROUP>

"ALL" means all groups on ''' + str(config.HOST_LIST) + '''.
"~<GROUP>" means exclud hosts on specified group.''')
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
"0" : silence mode;
"1" : only show host info;
"2" : only show one line output message;
"3" : show normal output message;
"4" : show verbose output message.''')
    parser.add_argument('-l', '--list_hosts',
                        nargs='+',
                        default=[],
                        help='List all or specified-group hosts on ' + str(config.HOST_LIST) + '''.
The format could be:
<GROUP>

"ALL" means all hosts on host list file.
"<GROUP>" means hosts on specified groups.''')
    parser.add_argument('-v', '--version',
                        action="store_true",
                        default=False,
                        help='Get batch_run version information.')

    args = parser.parse_args()

    # Get version.
    if args.version:
        print('Version : 1.1')
        print('Release Date : 2023.7')
        sys.exit(1)

    # List hosts
    if args.list_hosts:
        list_hosts(host_list_class, args.list_hosts)

    # Get hosts.
    specified_host_dic = get_specified_hosts(host_list_class, args.hosts, args.groups)

    if not specified_host_dic:
        print('*Error*: No valid host is specified.')
        sys.exit(1)

    # Get password.
    args.password = get_user_password(args.user, args.password)

    # Get commands.
    command_list = get_command_info(args.command, args.multi_commands_file)

    # Set output_message_level for parallel mode.
    if args.parallel and (args.output_message_level == 3):
        args.output_message_level = 1

    return (specified_host_dic, args.parallel, args.user, args.password, command_list, args.timeout, args.output_message_level)


def list_hosts(host_list_class, show_group_list):
    """
    List specified hosts.
    """
    for (group, group_dic) in host_list_class.host_list_dic.items():
        if ('all' in show_group_list) or ('ALL' in show_group_list) or (group in show_group_list):
            print('GROUP : [' + str(group) + ']')

            # Show hosts info.
            if 'hosts' in group_dic.keys():
                for host_ip in group_dic['hosts'].keys():
                    if 'host_name' in group_dic['hosts'][host_ip].keys():
                        host_name_list = group_dic['hosts'][host_ip]['host_name']
                    else:
                        host_name_list = ['',]

                    if 'ssh_port' in group_dic['hosts'][host_ip].keys():
                        ssh_port = group_dic['hosts'][host_ip]['ssh_port']
                    else:
                        ssh_port = ''

                    for host_name in host_name_list:
                        print('        %-15s  %s  %s' % (host_ip, host_name, ssh_port))

            # Show sub_groups info.
            if 'sub_groups' in group_dic.keys():
                for sub_group in group_dic['sub_groups']:
                    print('        ' + str(sub_group) + '/')

            # Show exclude_hosts info.
            if 'exclude_hosts' in group_dic.keys():
                if 'host_ip' in group_dic['exclude_hosts'].keys():
                    for host_ip in group_dic['exclude_hosts']['host_ip']:
                        print('        ~%s' % (host_ip))

                if 'host_name' in group_dic['exclude_hosts'].keys():
                    for host_name in group_dic['exclude_hosts']['host_name']:
                        print('        ~%s' % (host_name))

            # Show execlude_groups info.
            if 'exclude_groups' in group_dic.keys():
                for exclude_group in group_dic['exclude_groups']:
                    print('        ~' + str(exclude_group) + '/')

    sys.exit(0)


def get_specified_hosts(host_list_class, specified_host_list, specified_group_list):
    """
    Get specified hosts on specified_host_dic.
    specified_host_dic = {<host>: {'host_ip': [<host_ip>,], 'ssh_port':[<ssh_port>,]}}
    excluded_host_list = [<host>,]
    """
    specified_host_dic = {}
    excluded_host_list = []

    if specified_host_list or specified_group_list:
        # If groups are specified, parse and save.
        if specified_group_list:
            if ('all' in specified_group_list) or ('ALL' in specified_group_list):
                specified_group_list = list(host_list_class.host_list_dic.keys())

            (specified_host_dic, excluded_host_list) = common.parse_specified_groups(specified_group_list, host_list_class, specified_host_dic, excluded_host_list)

        # If hosts are specified, parse and save.
        if specified_host_list:
            if ('all' in specified_host_list) and ('ALL' in specified_host_list):
                specified_host_list = list(host_list_class.host_ip_dic.keys())

            (specified_host_dic, excluded_host_list) = common.parse_specified_hosts(specified_host_list, host_list_class, specified_host_dic, excluded_host_list)

        # Remove excluded hosts.
        copy_specified_host_dic = copy.deepcopy(specified_host_dic)

        for specified_host in copy_specified_host_dic.keys():
            # Remove specified_host from specified_host_dic.
            if specified_host in excluded_host_list:
                del specified_host_dic[specified_host]
            else:
                # Switch host_name to host_ip, and swich host_ip to host_name, judge again.
                switch_host_list = []

                if common.is_ip(specified_host):
                    if specified_host in host_list_class.host_ip_dic.keys():
                        if 'host_name' in host_list_class.host_ip_dic[specified_host].keys():
                            switch_host_list = host_list_class.host_ip_dic[specified_host]['host_name']
                else:
                    if specified_host in host_list_class.host_name_dic:
                        switch_host_list = host_list_class.host_name_dic[specified_host]

                for switch_host in switch_host_list:
                    if switch_host in excluded_host_list:
                        del specified_host_dic[specified_host]

    return specified_host_dic


def get_user_password(user, password):
    """
    Get password from argument or password.encrypted file.
    """
    if not password:
        password = ''
        encrypted_password_file = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config/password.encrypted'

        if os.path.exists(encrypted_password_file):
            password = common_password.get_password(encrypted_password_file, user)

        if not password:
            common.print_warning('*Warning*: user password is not specified!')

    return password


def get_command_info(command, multi_commands_file):
    """
    Get command list from argument or multi_commands_file.
    """
    command_list = []
    default_script_dir = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/scripts'

    if not multi_commands_file:
        # Try to find command on batchRun default scripts directory.
        if command:
            for (root, dirs, files) in os.walk(default_script_dir):
                if command[0] in files:
                    command[0] = str(root) + '/' + str(command[0])
                    break

            command_string = ' '.join(command)
            command_list.append(command_string)
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
                if re.match(r'^\s*$', line) or re.match(r'^\s*#.*$', line):
                    continue
                else:
                    command_list.append(line.strip())

    # Make sure at least one valid command is specified.
    if not command_list:
        common.print_error('*Error*: No valid command is specified!')
        sys.exit(1)

    return command_list


class BatchRun():
    def __init__(self, specified_host_dic, parallel, user, password, command_list, timeout, output_message_level):
        self.specified_host_dic = specified_host_dic
        self.parallel = parallel
        self.user = user
        self.password = password
        self.command_list = command_list
        self.timeout = timeout
        self.output_message_level = output_message_level

    def save_log(self, message, output_message_level_list=[0, 1, 2, 3, 4], nowrap=False):
        """
        Save output message into log file under config.LOG_DIR.
        """
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

    def get_ssh_command(self, host, host_ip, ssh_port):
        """
        Get full ssh command based on host & ssh_port.
        """
        # Default ssh setting.
        if config.DEFAULT_SSH_COMMAND:
            ssh_command = config.DEFAULT_SSH_COMMAND
        else:
            ssh_command = 'ssh -o StrictHostKeyChecking=no'

        if ssh_port:
            ssh_command = str(ssh_command) + ' -p ' + str(ssh_port)

        # Add user setting.
        if self.user:
            if host_ip:
                ssh_command = str(ssh_command) + ' ' + str(self.user) + '@' + str(host_ip)
            else:
                ssh_command = str(ssh_command) + ' ' + str(self.user) + '@' + str(host)
        else:
            if host_ip:
                ssh_command = str(ssh_command) + ' ' + str(host_ip)
            else:
                ssh_command = str(ssh_command) + ' ' + str(host)

        return ssh_command

    def execute_ssh_command(self, host, host_ip, ssh_port):
        """
        Get complate ssh command and execute it.
        """
        # Save log
        self.save_log('', [3, 4])

        if self.output_message_level == 2:
            if host_ip:
                self.save_log('>>> ' + str(host) + ' (' + str(host_ip) + ')', [2, ], nowrap=True)
            else:
                self.save_log('>>> ' + str(host), [2, ], nowrap=True)
        elif self.output_message_level in [1, 3, 4]:
            if host_ip:
                self.save_log('>>> ' + str(host) + ' (' + str(host_ip) + ')', [1, 3, 4])
            else:
                self.save_log('>>> ' + str(host), [1, 3, 4])

        # Get original ssh command.
        for (i, command) in enumerate(self.command_list):
            ssh_command = self.get_ssh_command(host, host_ip, ssh_port)
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
        """
        Main function, run commands parallel or serial.
        """
        if self.parallel:
            # Parallel mode.
            thread_list = []

            for host in self.specified_host_dic.keys():
                if 'host_ip' in self.specified_host_dic[host].keys():
                    for (i, host_ip) in enumerate(self.specified_host_dic[host]['host_ip']):
                        ssh_port = self.specified_host_dic[host]['ssh_port'][i]
                        thread = threading.Thread(target=self.execute_ssh_command, args=(host, host_ip, ssh_port))
                        thread.start()
                        thread_list.append(thread)
                else:
                    host_ip = None
                    ssh_port = None

                    if 'ssh_port' in self.specified_host_dic[host].keys():
                        ssh_port = self.specified_host_dic[host]['ssh_port']

                    thread = threading.Thread(target=self.execute_ssh_command, args=(host, host_ip, ssh_port))
                    thread.start()
                    thread_list.append(thread)

            # Join sub-threads with main-thread.
            for thread in thread_list:
                thread.join()
        else:
            # Serial mode.
            for host in self.specified_host_dic.keys():
                if 'host_ip' in self.specified_host_dic[host].keys():
                    for (i, host_ip) in enumerate(self.specified_host_dic[host]['host_ip']):
                        ssh_port = self.specified_host_dic[host]['ssh_port'][i]
                        self.execute_ssh_command(host, host_ip, ssh_port)
                else:
                    host_ip = None
                    ssh_port = None

                    if 'ssh_port' in self.specified_host_dic[host].keys():
                        ssh_port = self.specified_host_dic[host]['ssh_port']

                    self.execute_ssh_command(host, host_ip, ssh_port)


################
# Main Process #
################
def main():
    host_list_class = common.ParseHostList()
    (specified_host_dic, parallel, user, password, command_list, timeout, output_message_level) = read_args(host_list_class)
    my_batch_run = BatchRun(specified_host_dic, parallel, user, password, command_list, timeout, output_message_level)
    my_batch_run.run()


if __name__ == '__main__':
    main()
