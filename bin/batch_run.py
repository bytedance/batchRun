# -*- coding: utf-8 -*-
################################
# File Name   : batch_run.py
# Author      : liyanqing.1987
# Created On  : 2021-08-09 19:18:43
# Description : batchRun is a batch opration, asset management, and information
#               collection tool applied to HPC systems.
################################
import os
import re
import sys
import json
import time
import copy
import shutil
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
VERSION = 'V2.2'
VERSION_DATE = '2025.02.25'
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
<host_ip_file>
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
<group_file>
<group>
~<group>

"all | ALL" means all groups on ''' + str(config.host_list) + '''.
"~<GROUP>" means exclud specified group.''')
    parser.add_argument('-L', '--list',
                        action='store_true',
                        default=False,
                        help='List specified host(s)/group(s).')
    parser.add_argument('-u', '--user',
                        default=CURRENT_USER,
                        help='Specify the user identity for SSH login to specified host.')
    parser.add_argument('-p', '--password',
                        default='',
                        help='Specify the user password for SSH login to specified host.')
    parser.add_argument('-c', '--command',
                        nargs='+',
                        default=[],
                        help='Specify the command to run on specified remote host(s).')
    parser.add_argument('-P', '--parallel',
                        type=int,
                        default=1,
                        help='''Specify the parallelism of command execution with a number, default is "1" (serial mode).
"0" : Parallel mode, run all tasks in parallel;
"1" : Serial mode;
"n" : Parallel mode, run n tasks in parallel.''')
    parser.add_argument('-t', '--timeout',
                        type=int,
                        help='Specify the timeout for SSH, which defaults to ' + str(config.serial_timeout) + ' seconds in serial and ' + str(config.parallel_timeout) + ' seconds in parallel.')
    parser.add_argument('-l', '--output_message_level',
                        type=int,
                        choices=[0, 1, 2, 3, 4],
                        default=3,
                        help='''Specify output message level, which defaults to "3" in serial and "0" in parallel.
"0" : print host info;
"1" : print command output message;
"2" : print host info and the first line of the command output message;
"3" : print host info and complete command output message;
"4" : print verbose information with ssh command.''')
    parser.add_argument('-o', '--output_file',
                        default='',
                        help='Export output message of command to specified file instead of on the screen.')
    parser.add_argument('-g', '--gui',
                        action='store_true',
                        default=False,
                        help='Open batchRun with GUI format.')
    parser.add_argument('-v', '--version',
                        action="store_true",
                        default=False,
                        help='Show batchRun version information.')

    args = parser.parse_args()

    # Enable GUI mode.
    if args.gui:
        os.system(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/bin/batch_run_gui')
        sys.exit(0)

    # Get batchRun version information.
    if args.version:
        common.bprint('Version : ' + str(VERSION))
        common.bprint('Release : ' + str(VERSION_DATE))
        sys.exit(0)

    # Check hosts/groups settings.
    if (not args.hosts) and (not args.groups):
        common.bprint('Neither of argument "--hosts" or "--groups" is specified.', level='Error')
        sys.exit(1)

    # Analyze host file.
    if (len(args.hosts) == 1) and os.path.isfile(args.hosts[0]):
        with open(args.hosts[0], 'r') as HF:
            args.hosts = []

            for line in HF.readlines():
                if (not re.match(r'^\s*#.*$', line)) and (not re.match(r'^\s*$', line)):
                    args.hosts.append(line.strip())

    # Analyze group file.
    if (len(args.groups) == 1) and os.path.isfile(args.groups[0]):
        with open(args.groups[0], 'r') as GF:
            args.groups = []

            for line in GF.readlines():
                if (not re.match(r'^\s*#.*$', line)) and (not re.match(r'^\s*$', line)):
                    args.groups.append(line.strip())

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

    # Check command setting.
    if not args.command:
        common.bprint('No command is specified.', level='Error')
        sys.exit(1)
    else:
        # Try to find command under batchRun scripts directory.
        scripts_dir = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/scripts'
        command_name = args.command[0]

        for root, dirs, files in os.walk(scripts_dir):
            if command_name in files:
                args.command[0] = os.path.join(root, command_name)

        # Filter illegal command.
        format_command = ' '.join(args.command)
        format_command = re.sub(r'\\', '', format_command)

        for illegal_command in config.illegal_command_list:
            if (format_command in config.illegal_command_list) or re.match(r'^' + str(illegal_command) + '$', format_command):
                common.bprint('Illegal command!', level='Error')
                sys.exit(1)

    # Reset default timeout setting.
    if not args.timeout:
        if args.parallel == 1:
            args.timeout = config.serial_timeout
        else:
            args.timeout = config.parallel_timeout

    # Set output_message_level for parallel mode.
    if (args.parallel != 1) and (not args.output_file) and (args.output_message_level in [3, 4]):
        common.bprint('Switch output_message_level to "0" on parallel mode.', level='Warning')
        args.output_message_level = 0

    return specified_host_dic, args.user, args.password, args.command, args.parallel, args.timeout, args.output_message_level, args.output_file


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


class BatchRun():
    def __init__(self, specified_host_dic, user, password, command_list, parallel, timeout, output_message_level, output_file):
        self.specified_host_dic = specified_host_dic
        self.user = user
        self.password = password
        self.command_list = self.preprocess_command_string(command_list)
        self.parallel = parallel
        self.timeout = timeout
        self.output_message_level = output_message_level
        self.output_file = output_file

        # Below self.command_missing_compile_list is only for bash/csh/tcsh.
        self.command_missing_compile_list = [re.compile(r'^bash:\s+(\S+):\s+command not found...\s*$'), re.compile(r'^bash:\s+(\S+):\s+No such file or directory\s*$'), re.compile(r'^(\S+):\s+Command not found.$')]
        self.timeout_string_list = ['Timeout exceeded', 'pexpect.exceptions.TIMEOUT']

        self.password_host_list = self.get_password_hosts()

    def preprocess_command_string(self, command_list):
        """
        Remove unreasonable escape for "-".
        """
        new_command_list = []

        for command_string in command_list:
            if re.search(r'\\-', command_string):
                command_string = re.sub(r'\\-', '-', command_string)

            new_command_list.append(command_string)

        return new_command_list

    def save_command(self):
        """
        Save command info into command history file under config.db_path/log.
        """
        if hasattr(config, 'db_path') and config.db_path:
            # Create log dir.
            log_dir = str(config.db_path) + '/log'
            common.create_dir(log_dir, permission=0o1777)
            log_user_dir = str(log_dir) + '/' + str(CURRENT_USER)
            common.create_dir(log_user_dir, permission=0o700)

            # Write command history file.
            command_history_file = str(log_user_dir) + '/command.his'
            log_file = str(log_user_dir) + '/' + str(START_TIME)

            with open(command_history_file, 'a') as CHF:
                start_date = START_TIME.split('_')[0]
                start_time = START_TIME.split('_')[1]
                cmd_string = ' '.join(sys.argv).strip()
                command_dic = {'date': start_date, 'time': start_time, 'user': CURRENT_USER, 'login_user': LOGIN_USER, 'command': cmd_string, 'log': log_file}
                CHF.write(str(json.dumps(command_dic, ensure_ascii=False)) + '\n')

    def save_log(self, message, end='\n'):
        """
        Save output message into log file under config.db_path/log.
        """
        if hasattr(config, 'db_path') and config.db_path:
            # Write log file.
            log_file = str(config.db_path) + '/log/' + str(CURRENT_USER) + '/' + str(START_TIME)

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
                common.create_dir(output_dir, permission=0o777)

            # Write output file.
            with open(output_file, 'a') as OF:
                OF.write(str(message) + str(end))
        else:
            print(message, end=end)

    def get_password_hosts(self):
        """
        Get all specified host(s) from user password file.
        """
        password_host_list = []
        password_file = str(config.db_path) + '/password/' + str(self.user)

        if os.path.exists(password_file):
            with open(password_file, 'r') as PF:
                for line in PF.readlines():
                    host_name = line.split()[1]

                    if host_name != 'default':
                        password_host_list.append(host_name)

        return password_host_list

    def get_ssh_command(self, host, host_ip, ssh_port, command_list):
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

        # Add specified command.
        command_string = ' '.join(command_list)

        if '"' in command_string:
            ssh_command = str(ssh_command) + " '" + str(command_string) + "'"
        else:
            ssh_command = str(ssh_command) + ' "' + str(command_string) + '"'

        return ssh_command

    def get_right_host_format(self, host):
        """
        For host, return host by default.
        If host_ip in self.password_host_list, return host_ip.
        If host_name in self.password_host_list, return host_name.
        """
        right_host_format = host

        if self.password_host_list:
            if 'host_name' in self.specified_host_dic[host]:
                for host_name in self.specified_host_dic[host]['host_name']:
                    if host_name in self.password_host_list:
                        right_host_format = host_name
                        break

            if (right_host_format == host) and ('host_ip' in self.specified_host_dic[host]):
                for host_ip in self.specified_host_dic[host]['host_ip']:
                    if host_ip in self.password_host_list:
                        right_host_format = host_ip
                        break

        return right_host_format

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

        # Get ssh command.
        ssh_command = self.get_ssh_command(host, host_ip, ssh_port, self.command_list)

        if self.output_message_level == 4:
            self.save_out('    ' + str(ssh_command), host=host)
            self.save_log('    ' + str(ssh_command))

        # Execute ssh command.
        # ssh_run usage:
        # common_secure.ssh_run(ssh_command, user, host, password, timeout=10)
        right_host_format = self.get_right_host_format(host)
        stdout_lines = common_secure.ssh_run(ssh_command, self.user, right_host_format, self.password, self.timeout)

        # Print command output message as expected method.
        if self.output_message_level == 4:
            self.save_out('    ==== output ====', host=host)
            self.save_log('    ==== output ====')

        # Auto-rerun for "command missing" and "timeout" conditions.
        missing_command = self.check_command_missing(stdout_lines)
        missing_command_path = shutil.which(missing_command)

        if missing_command and missing_command_path:
            if self.output_message_level == 4:
                self.save_out('    Command missing, scp and rerun.', host=host)
                self.save_log('    Command missing, scp and rerun.')

            stdout_lines = self.scp_and_rerun(host, host_ip, ssh_port, missing_command_path)
        elif self.check_timeout(stdout_lines):
            if self.output_message_level == 4:
                self.save_out('    Ssh timeout, rerun.', host=host)
                self.save_log('    Ssh timeout, rerun.')

            right_host_format = self.get_right_host_format(host)
            stdout_lines = common_secure.ssh_run(ssh_command, self.user, right_host_format, self.password, self.timeout)

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

    def check_command_missing(self, stdout_lines):
        """
        Search for command missing string on stdout_lines.
        """
        if stdout_lines and (len(stdout_lines) == 1):
            for line in stdout_lines:
                for command_missing_compile in self.command_missing_compile_list:
                    if command_missing_compile.match(line):
                        my_match = command_missing_compile.match(line)
                        return my_match.group(1)

        return ''

    def check_timeout(self, stdout_lines):
        """
        Search for auto rerun string on stdout_lines.
        """
        if stdout_lines:
            for line in stdout_lines:
                for auto_rerun_string in self.timeout_string_list:
                    if re.search(auto_rerun_string, line):
                        return True

        return False

    def scp_and_rerun(self, host, host_ip, ssh_port, missing_command_path):
        """
        If command missing on remote host, scp missing_command_path to remove host local and rerun.
        """
        # Scp command/script to remove host /tmp directory.
        script_name = os.path.basename(missing_command_path)
        local_script_path = '/tmp/' + str(script_name)

        if ssh_port:
            scp_command = 'scp -p -P ' + str(ssh_port) + ' ' + str(missing_command_path) + ' ' + str(host) + ':' + str(local_script_path)
        else:
            scp_command = 'scp -p ' + str(missing_command_path) + ' ' + str(host) + ':' + str(local_script_path)

        common_secure.scp_run(scp_command, self.user, host, self.password, self.timeout)

        # Re-run command.
        command_list = copy.deepcopy(self.command_list)
        command_list[0] = local_script_path
        ssh_command = self.get_ssh_command(host, host_ip, ssh_port, command_list)
        right_host_format = self.get_right_host_format(host)
        stdout_lines = common_secure.ssh_run(ssh_command, self.user, right_host_format, self.password, self.timeout)

        return stdout_lines

    def run(self):
        """
        Main function, run commands in parallel or serial mode.
        """
        # Save command
        self.save_command()
        start_second = time.time()

        if self.parallel == 1:
            host_num = self.serial_run()
        else:
            host_num = self.parallel_run()

        end_second = time.time()
        runtime = self.get_runtime(start_second, end_second)

        print('\nTotal ' + str(host_num) + ' hosts.  (Runtime: ' + str(runtime) + ')')

    def serial_run(self):
        """
        Run commands in serial mode.
        """
        host_num = 0

        for host in self.specified_host_dic.keys():
            if 'host_ip' in self.specified_host_dic[host]:
                for (i, host_ip) in enumerate(self.specified_host_dic[host]['host_ip']):
                    ssh_port = self.specified_host_dic[host]['ssh_port'][i]
                    host_num += 1
                    self.execute_ssh_command(host, host_ip, ssh_port)
            else:
                host_ip = None
                ssh_port = None

                if 'ssh_port' in self.specified_host_dic[host]:
                    ssh_port = self.specified_host_dic[host]['ssh_port']

                host_num += 1
                self.execute_ssh_command(host, host_ip, ssh_port)

        return host_num

    def parallel_run(self):
        """
        Run commands in parallel mode.
        """
        host_num = 0
        thread_list = []

        # Collect all commands into thread_list.
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

        # Run commands in thread_list according to specified parallelism.
        alive_thread_list = []

        for thread in thread_list:
            host_num += 1
            thread.join()
            alive_thread_list.append(thread)

            while self.parallel and (len(alive_thread_list) >= self.parallel):
                time.sleep(1)

                for alive_thread in alive_thread_list:
                    if not alive_thread.is_alive():
                        alive_thread_list.remove(alive_thread)

        return host_num

    def get_runtime(self, start_second, end_second):
        """
        runtime = end_second - start_second
        """
        run_second = int(end_second) - int(start_second)
        runtime = str(run_second) + ' seconds'

        if run_second >= 60:
            result = divmod(run_second, 60)
            run_minute = result[0]
            run_second_remainder = result[1]

            if run_minute == 1:
                runtime = str(run_minute) + ' minute'
            else:
                runtime = str(run_minute) + ' minutes'

            if run_second_remainder:
                if run_second_remainder == 1:
                    runtime = str(runtime) + ' ' + str(run_second_remainder) + ' second'
                else:
                    runtime = str(runtime) + ' ' + str(run_second_remainder) + ' seconds'

        return runtime


################
# Main Process #
################
def main():
    (specified_host_dic, user, password, command_list, parallel, timeout, output_message_level, output_file) = read_args()
    my_batch_run = BatchRun(specified_host_dic, user, password, command_list, parallel, timeout, output_message_level, output_file)
    my_batch_run.run()


if __name__ == '__main__':
    main()
