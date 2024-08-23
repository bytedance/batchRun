# -*- coding: utf-8 -*-
################################
# File Name   : batch_run.py
# Author      : liyanqing.1987
# Created On  : 2021-08-09 19:18:43
# Description : batchRun is an open source IT automation engine, which is used for
#               task push and information retrieval across multiple linux servers,
#               just like pssh or ansible.
################################
import os
import re
import sys
import json
import copy
import getpass
import datetime
import argparse
import threading

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common
import common_secure

os.environ['PYTHONUNBUFFERED'] = '1'
START_TIME = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
CURRENT_USER = getpass.getuser()
LOGIN_USER = common.get_login_user()


def read_args():
    """
    Read in arguments.
    """
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-H', '--hosts',
                        nargs='+',
                        default=[],
                        help='''Specify host(s) with below format:
<host_ip>
<host_ip>:<ssh_port>
<host_name>
<host_name>:<ssh_port>
~<host_ip>
~<host_name>

"all | ALL" means all hosts on ''' + str(config.host_list) + '''.
"~<host>" means exclud specified host.''')
    parser.add_argument('-G', '--groups',
                        nargs='+',
                        default=[],
                        help='''Specify host group(s) with below format:
<GROUP>
~<GROUP>

"all | ALL" means all groups on ''' + str(config.host_list) + '''.
"~<GROUP>" means exclud hosts on specified group.''')
    parser.add_argument('-L', '--list',
                        action='store_true',
                        default=False,
                        help='List specified hosts/groups.')
    parser.add_argument('-u', '--user',
                        default=CURRENT_USER,
                        help='Specify the user name when loggin into the host in ssh format.')
    parser.add_argument('-p', '--password',
                        default='',
                        help='Specify the user password when logging into the host in ssh format.')
    parser.add_argument('-c', '--command',
                        nargs='+',
                        default=[],
                        help='Specify command you want run on specified host(s).')
    parser.add_argument('-s', '--script',
                        nargs='+',
                        default=[],
                        help='Specify script you want run on specified host(s), will copy script to host /tmp directory.')
    parser.add_argument('-P', '--parallel',
                        action='store_true',
                        default=False,
                        help='Run command/script parallel on specified host(s), default is in serial.')
    parser.add_argument('-t', '--timeout',
                        type=int,
                        default=config.timeout,
                        help='Specify ssh timeout, default is ' + str(config.timeout) + ' seconds.')
    parser.add_argument('-l', '--output_message_level',
                        type=int,
                        choices=[0, 1, 2, 3, 4],
                        default=3,
                        help='''Specify output message level, default is "3".
"0" : print host info;
"1" : print output message;
"2" : print host info and the first line of the output message;
"3" : print host info and complete output message;
"4" : print verbose information.''')
    parser.add_argument('-o', '--output_file',
                        default='',
                        help='Export output message of command/script to specified file instead of on the screen.')
    parser.add_argument('-v', '--version',
                        action="store_true",
                        default=False,
                        help='Show batchRun version information.')

    args = parser.parse_args()

    # Get batchRun version information.
    if args.version:
        common.bprint('Version : 1.2')
        common.bprint('Release : 2024.8.23')
        sys.exit(0)

    # Check hosts/groups settings.
    if (not args.hosts) and (not args.groups):
        common.bprint('Neither of argument "--hosts" or "--groups" is specified.', level='Error')
        sys.exit(1)

    # Get specified host(s) info.
    host_list_class = common.ParseHostList()
    (specified_host_dic, expected_group_list, excluded_group_list) = get_specified_hosts(host_list_class, args.hosts, args.groups)

    if not specified_host_dic:
        common.bprint('No valid host is specified.', level='Error')
        sys.exit(1)

    # List hosts.
    if args.list:
        list_hosts(host_list_class, specified_host_dic, expected_group_list, excluded_group_list, args.output_file)
        sys.exit(0)

    # Check command & script.
    if args.command and args.script:
        common.bprint('Cannot specify arguments "--command" and "--script" the same time.', level='Error')
        sys.exit(1)
    elif (not args.command) and (not args.script):
        common.bprint('Neither of argument "--command" or "--script" is specified.', level='Error')
        sys.exit(1)
    elif args.script:
        args.script = update_script_setting(args.script)

        if not args.script:
            common.bprint('No valid script is specified.', level='Error')
            sys.exit(1)

    # Set output_message_level for parallel mode.
    if args.parallel and (not args.output_file) and (args.output_message_level in [1, 2, 3, 4]):
        common.bprint('Switch output_message_level to "0" on parallel mode.', level='Warning')
        args.output_message_level = 0

    return specified_host_dic, args.user, args.password, args.command, args.script, args.parallel, args.timeout, args.output_message_level, args.output_file


def get_specified_hosts(host_list_class, specified_host_list, specified_group_list):
    """
    specified_host_dic = {<host>: {'host_name': [<host_name>,], 'ssh_port': <ssh_port>, 'groups': [<group>,]}}
    or
    specified_host_dic = {<host>: {'host_ip': [<host_ip>,], 'ssh_port': [<ssh_port>,], 'groups': [[<group>,],]}}
    or
    specified_host_dic = {<host>: {'ssh_port': <ssh_port>}}
    """
    specified_host_dic = {}
    excluded_host_list = []
    expected_group_list = []
    excluded_group_list = []

    if specified_host_list or specified_group_list:
        # If groups are specified, parse and save.
        if specified_group_list:
            (specified_host_dic, excluded_host_list, expected_group_list, excluded_group_list) = common.parse_specified_groups(specified_group_list, host_list_class, specified_host_dic, excluded_host_list, expected_group_list, excluded_group_list)

        # If hosts are specified, parse and save.
        if specified_host_list:
            (specified_host_dic, excluded_host_list, expected_group_list, excluded_group_list) = common.parse_specified_hosts(specified_host_list, host_list_class, specified_host_dic, excluded_host_list, expected_group_list, excluded_group_list)

    return specified_host_dic, expected_group_list, excluded_group_list


def list_hosts(host_list_class, specified_host_dic, expected_group_list, excluded_group_list, output_file):
    """
    List specified hosts.
    """
    if output_file:
        with open(output_file, 'w') as OF:
            OF.write(str(json.dumps(specified_host_dic, ensure_ascii=False, indent=4)) + '\n')
            common.bprint('* Host(s) info has been saved into "' + str(output_file) + '".')
    else:
        remaining_host_list = list(specified_host_dic.keys())

        for (group, group_dic) in host_list_class.host_list_dic.items():
            if (group not in excluded_group_list) and (group in expected_group_list):
                print('GROUP : [' + str(group) + ']')

                # Show hosts info.
                if 'hosts' in group_dic:
                    for host_ip in group_dic['hosts'].keys():
                        if 'host_name' in group_dic['hosts'][host_ip]:
                            host_name_list = group_dic['hosts'][host_ip]['host_name']
                        else:
                            host_name_list = ['',]

                        if 'ssh_port' in group_dic['hosts'][host_ip]:
                            ssh_port = group_dic['hosts'][host_ip]['ssh_port']
                        else:
                            ssh_port = ''

                        for host_name in host_name_list:
                            if (host_ip in specified_host_dic) or (host_name in specified_host_dic):
                                print('        %-15s  %s  %s' % (host_ip, host_name, ssh_port))

                                if (host_ip in specified_host_dic) and (host_ip in remaining_host_list):
                                    remaining_host_list.remove(host_ip)
                                elif (host_name in specified_host_dic) and (host_name in remaining_host_list):
                                    remaining_host_list.remove(host_name)

                # Show sub_groups info.
                if 'sub_groups' in group_dic:
                    for sub_group in group_dic['sub_groups']:
                        print('        ' + str(sub_group) + '/')

                # Show exclude_hosts info.
                if 'exclude_hosts' in group_dic:
                    if 'host_ip' in group_dic['exclude_hosts']:
                        for host_ip in group_dic['exclude_hosts']['host_ip']:
                            print('        ~%s' % (host_ip))

                    if 'host_name' in group_dic['exclude_hosts']:
                        for host_name in group_dic['exclude_hosts']['host_name']:
                            print('        ~%s' % (host_name))

                # Show execlude_groups info.
                if 'exclude_groups' in group_dic:
                    for exclude_group in group_dic['exclude_groups']:
                        print('        ~' + str(exclude_group) + '/')

        if remaining_host_list:
            print('UNRECOGNIZED HOST :')

            for host in remaining_host_list:
                print('        ' + str(host))


def update_script_setting(script_list):
    """
    Get real script path, and splice the complate command line.
    """
    if os.path.exists(script_list[0]):
        script_list[0] = os.path.realpath(script_list[0])
        return script_list
    else:
        default_script_dir = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/scripts'

        for (root, dirs, files) in os.walk(default_script_dir):
            if script_list[0] in files:
                script_list[0] = str(root) + '/' + str(script_list[0])
                return script_list

    return []


def create_dir(dir_path, permission=0o777):
    """
    Create dir with specified permission.
    """
    if not os.path.exists(dir_path):
        try:
            os.makedirs(dir_path)
            os.chmod(dir_path, permission)
        except Exception as error:
            common.bprint('Failed on creating directory "' + str(dir_path) + '", ' + str(error), level='Error')
            sys.exit(1)


class BatchRun():
    def __init__(self, specified_host_dic, user, password, command_list, script_list, parallel, timeout, output_message_level, output_file):
        self.specified_host_dic = specified_host_dic
        self.user = user
        self.password = password
        self.command_list = command_list
        self.script_list = script_list
        self.parallel = parallel
        self.timeout = timeout
        self.output_message_level = output_message_level
        self.output_file = output_file

    def save_log(self, message, end='\n'):
        """
        Save output message into log file under config.db_path/log.
        """
        if hasattr(config, 'db_path') and config.db_path:
            # Create log dir.
            log_dir = str(config.db_path) + '/log'
            create_dir(log_dir)
            log_user_dir = str(log_dir) + '/' + str(CURRENT_USER)
            create_dir(log_user_dir, permission=0o700)

            # Write log file.
            log_file = str(log_user_dir) + '/' + str(START_TIME)

            if not os.path.exists(log_file):
                with open(log_file, 'a') as LF:
                    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    cmd_string = ' '.join(sys.argv)
                    his_dic = {'time': current_time, 'user': CURRENT_USER, 'login_user': LOGIN_USER, 'command': cmd_string.strip()}
                    LF.write(str(json.dumps(his_dic, ensure_ascii=False)) + '\n')
                    LF.write('\n')

            with open(log_file, 'a') as LF:
                LF.write(str(message) + str(end))

    def save_out(self, message, end='\n', host=''):
        """
        Print output message on screen, or save output message into output file.
        """
        if self.output_file:
            # Update output_file with "HOST".
            output_file = self.output_file

            if host:
                output_file = re.sub('HOST', host, output_file)

            # Create output_dir if not exists.
            output_dir = os.path.dirname(output_file)

            if output_dir and (not os.path.exists(output_dir)):
                create_dir(output_dir)

            # Write output file.
            with open(output_file, 'a') as OF:
                OF.write(str(message) + str(end))
        else:
            print(message, end=end)

    def get_ssh_command(self, host, host_ip, ssh_port):
        """
        Get full ssh command based on host & ssh_port.
        """
        # Default ssh setting.
        if config.default_ssh_command:
            ssh_command = config.default_ssh_command
        else:
            ssh_command = 'ssh -o StrictHostKeyChecking=no -t -q'

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
        if self.output_message_level in [3, 4]:
            self.save_out('', host=host)
            self.save_log('')

        if self.output_message_level == 2:
            self.save_out('>>> ' + str(host), end=' ', host=host)
            self.save_log('>>> ' + str(host), end=' ')
        elif self.output_message_level in [0, 3, 4]:
            if host_ip:
                self.save_out('>>> ' + str(host) + ' (' + str(host_ip) + ')', host=host)
                self.save_log('>>> ' + str(host) + ' (' + str(host_ip) + ')')
            else:
                self.save_out('>>> ' + str(host), host=host)
                self.save_log('>>> ' + str(host))

        # Copy script to host local with script-mode.
        if self.script_list:
            script_name = os.path.basename(self.script_list[0])

            if ssh_port:
                scp_command = 'scp -P ' + str(ssh_port) + ' ' + str(self.script_list[0]) + ' ' + str(host) + ':/tmp/' + str(script_name)
            else:
                scp_command = 'scp ' + str(self.script_list[0]) + ' ' + str(host) + ':/tmp/' + str(script_name)

            if self.output_message_level == 4:
                self.save_out('    ' + str(scp_command), host=host)
                self.save_log('    ' + str(scp_command))

            # scp_run usage:
            # common_secure.scp_run(ssh_command, user, host, password, timeout=10)
            stdout_lines = common_secure.scp_run(scp_command, self.user, host, self.password, self.timeout)

        # Get original ssh command.
        ssh_command = self.get_ssh_command(host, host_ip, ssh_port)

        if self.command_list:
            ssh_command = str(ssh_command) + ' ' + str(' '.join(self.command_list))
        elif self.script_list:
            script_list = copy.deepcopy(self.script_list)
            script_list[0] = '/tmp/' + str(os.path.basename(self.script_list[0]))
            ssh_command = str(ssh_command) + ' ' + str(' '.join(script_list))

        ssh_command = re.sub("'", "\\'", ssh_command)
        ssh_command = re.sub('"', '\\"', ssh_command)

        if self.output_message_level == 4:
            self.save_out('    ' + str(ssh_command), host=host)
            self.save_log('    ' + str(ssh_command))

        # Execute ssh command.
        # ssh_run usage:
        # common_secure.ssh_run(ssh_command, user, host, password, timeout=10)
        stdout_lines = common_secure.ssh_run(ssh_command, self.user, host, self.password, self.timeout)

        # Print command output message as expected method.
        if self.output_message_level == 4:
            self.save_out('    ==== output ====', host=host)
            self.save_log('    ==== output ====')

        if not stdout_lines:
            if self.output_message_level == 2:
                self.save_out('', host=host)
                self.save_log('')
        else:
            for stdout_line in stdout_lines:
                stdout_line = stdout_line.strip()

                if stdout_line:
                    if self.output_message_level in [1, 2, 3, 4]:
                        self.save_out('    ' + str(stdout_line), host=host)

                    self.save_log('    ' + str(stdout_line))

                    if self.output_message_level == 2:
                        break

        if self.output_message_level == 4:
            self.save_out('    ================', host=host)
            self.save_log('    ================')

    def run(self):
        """
        Main function, run commands parallel or serial.
        """
        if self.parallel:
            # Parallel mode.
            thread_list = []

            for host in self.specified_host_dic.keys():
                if 'host_ip' in self.specified_host_dic[host]:
                    for (i, host_ip) in enumerate(self.specified_host_dic[host]['host_ip']):
                        ssh_port = self.specified_host_dic[host]['ssh_port'][i]
                        thread = threading.Thread(target=self.execute_ssh_command, args=(host, host_ip, ssh_port))
                        thread.start()
                        thread_list.append(thread)
                else:
                    host_ip = None
                    ssh_port = None

                    if 'ssh_port' in self.specified_host_dic[host]:
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
                if 'host_ip' in self.specified_host_dic[host]:
                    for (i, host_ip) in enumerate(self.specified_host_dic[host]['host_ip']):
                        ssh_port = self.specified_host_dic[host]['ssh_port'][i]
                        self.execute_ssh_command(host, host_ip, ssh_port)
                else:
                    host_ip = None
                    ssh_port = None

                    if 'ssh_port' in self.specified_host_dic[host]:
                        ssh_port = self.specified_host_dic[host]['ssh_port']

                    self.execute_ssh_command(host, host_ip, ssh_port)


################
# Main Process #
################
def main():
    (specified_host_dic, user, password, command_list, script_list, parallel, timeout, output_message_level, output_file) = read_args()
    my_batch_run = BatchRun(specified_host_dic, user, password, command_list, script_list, parallel, timeout, output_message_level, output_file)
    my_batch_run.run()


if __name__ == '__main__':
    main()
