import os
import re
import sys

CWD = os.getcwd()
PYTHON_PATH = os.path.dirname(os.path.abspath(sys.executable))


def check_python_version():
    """
    Check python version.
    python3 is required, anaconda3 is better.
    """
    print('>>> Check python version.')

    current_python = sys.version_info[:2]
    required_python = (3, 12)

    if current_python < required_python:
        sys.stderr.write("""
============================
Not suggested python version
============================
batchRun requires Python {}.{},
Current python is Python {}.{}.
""".format(*(required_python + current_python)))
        sys.exit(1)
    else:
        print('    Required python version : ' + str(required_python))
        print('    Current  python version : ' + str(current_python))


def get_ld_library_path_setting():
    """
    Get variable LD_LIBRARY_PATH setting for batchRun.

    Replaces only the trailing "/bin" of the python path (not every "/bin" in
    it) and uses plain string replacement (not regex) so dots in versioned path
    segments like ".../python3/3.12.12/bin" are not treated as regex
    metacharacters when stripping an already-present duplicate.
    """
    if PYTHON_PATH.endswith('/bin'):
        python_lib_path = PYTHON_PATH[:-4] + '/lib'
    else:
        python_lib_path = re.sub(r'/bin$', '/lib', PYTHON_PATH)

    ld_library_path_setting = 'export LD_LIBRARY_PATH=$BATCH_RUN_INSTALL_PATH/lib:' + str(python_lib_path) + ':'

    if 'LD_LIBRARY_PATH' in os.environ:
        current = str(os.environ['LD_LIBRARY_PATH'])

        if python_lib_path in current:
            # Strip an already-present duplicate using plain string replace.
            ld_library_path_setting = str(ld_library_path_setting) + current.replace(str(python_lib_path) + ':', '')
        else:
            ld_library_path_setting = str(ld_library_path_setting) + current

    return ld_library_path_setting


def gen_batch_run():
    """
    Generate script <BATCH_RUN_INSTALL_PATH>/bin/batch_run.
    """
    batch_run = str(CWD) + '/bin/batch_run'
    ld_library_path_setting = get_ld_library_path_setting()

    print('')
    print('>>> Generate script "' + str(batch_run) + '".')

    try:
        with open(batch_run, 'w') as BR:
            BR.write("""#!/bin/bash

# Set python3 path.
export PATH=""" + str(PYTHON_PATH) + """:$PATH

# Set install path.
export BATCH_RUN_INSTALL_PATH=""" + str(CWD) + """

# Set LD_LIBRARY_PATH.
""" + str(ld_library_path_setting) + """

# Set input method for Qt5 (auto-detect ibus/fcitx).
if [ -z "$QT_IM_MODULE" ]; then
    if pgrep -x ibus-daemon > /dev/null 2>&1; then
        export QT_IM_MODULE=ibus
    elif pgrep -x fcitx > /dev/null 2>&1 || pgrep -x fcitx5 > /dev/null 2>&1; then
        export QT_IM_MODULE=fcitx
    fi
fi

# Preprocess "command" argument.
pre_arg=""
num=-1

for arg in "$@"
do
    if [[ $pre_arg == "-c" ]] || [[ $pre_arg == "--command" ]]; then
        if [[ $arg =~ " " ]] && [[ $arg =~ "-" ]]; then
            arg=`echo "$arg" | sed 's/-/\\\\\\-/g'`
        fi
    fi

    num=$(($num+1))
    args[$num]="$arg"
    pre_arg=$arg
done

# Execute batch_run.py.
python3 $BATCH_RUN_INSTALL_PATH/bin/batch_run.py ${args[*]}
""")

        os.chmod(batch_run, 0o755)
    except Exception as err:
        print('*Error*: Failed on generating script "' + str(batch_run) + '": ' + str(err))
        sys.exit(1)


def gen_shell_tools():
    """
    Generate shell scripts under <BATCH_RUN_INSTALL_PATH>.
    """
    tool_list = ['bin/batch_run_gui', 'tools/cleanup_log', 'tools/cleanup_db', 'tools/encrypt_python', 'tools/network_scan', 'tools/patch', 'tools/sample_host_info', 'tools/sample_host_queue', 'tools/sample_host_stat', 'tools/save_password', 'tools/show_top_file', 'tools/switch_etc_hosts']
    ld_library_path_setting = get_ld_library_path_setting()

    for tool_name in tool_list:
        tool = str(CWD) + '/' + str(tool_name)

        print('')
        print('>>> Generate script "' + str(tool) + '".')

        try:
            with open(tool, 'w') as SP:
                SP.write("""#!/bin/bash

# Set python3 path.
export PATH=""" + str(PYTHON_PATH) + """:$PATH

# Set install path.
export BATCH_RUN_INSTALL_PATH=""" + str(CWD) + """

# Set LD_LIBRARY_PATH.
""" + str(ld_library_path_setting) + """

# Execute """ + str(tool_name) + """.py.
python3 $BATCH_RUN_INSTALL_PATH/""" + str(tool_name) + '.py "$@"')

            os.chmod(tool, 0o755)
        except Exception as error:
            print('*Error*: Failed on generating script "' + str(tool) + '": ' + str(error))
            sys.exit(1)


def gen_config_file():
    """
    Generate config file <BATCH_RUN_INSTALL_PATH>/config/config.py.
    """
    config_file = str(CWD) + '/config/config.py'

    print('')
    print('>>> Generate config file "' + str(config_file) + '".')

    if os.path.exists(config_file):
        print('*Warning*: config file "' + str(config_file) + '" already exists, will not update it.')
    else:
        try:
            host_list = str(CWD) + '/config/host.list'

            with open(config_file, 'w') as CF:
                CF.write("""# Specify host list, default is "host.list" on current configure directory.
host_list = '""" + str(host_list) + """'

# Specify the database directory.
db_path = '""" + str(CWD) + """/db'

# Default ssh command.
default_ssh_command = 'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ConnectionAttempts=2 -o GSSAPIAuthentication=no -t -q'

# Define timeout for ssh command, unit is "second".
serial_timeout = 10
parallel_timeout = 20

# Upper bound on parallel ssh sessions.
max_parallel = 512

# Two-phase retry for hosts whose output file is missing/empty.
retry_failed_hosts = True

# Illegal command list.
illegal_command_list = ['rm -rf /', 'rm -rf ~', 'rm -rf ~/']

# Command for switch_etc_hosts.
switch_etc_hosts_command = '""" + str(CWD) + """/tools/switch_etc_hosts --rewrite --tool batchRun'

# Command for network_scan.
network_scan_command = '""" + str(CWD) + """/tools/network_scan --alive'

# Command for sample_host_info.
sample_host_info_command = '""" + str(CWD) + """/tools/sample_host_info --groups ALL'

# Command for sample_host_queue.
sample_host_queue_command = '""" + str(CWD) + """/tools/sample_host_queue --groups ALL'

# Command for sample_host_stat.
sample_host_stat_command = '""" + str(CWD) + """/tools/sample_host_stat --groups ALL'

# Log retention days (auto-cleanup log files older than this).
log_retention_days = 30

# History retention days for each db sub-directory (used by cleanup_db tool).
history_retention_days = {
    'host_stat': 7,      # *.stat/*.top under <date>/<time>/, biggest consumer
    'host_asset': 30,    # host_asset_<date>.json, kingdee_assets_*_<date>_<time>.json
    'host_info': 30,     # host_info.json.<timestamp> snapshots (*.info kept, overwritten per host)
    'host_queue': 30,    # host_queue.json.<timestamp> snapshots
    'ai_report': 30,     # *_analysis_<timestamp>.html reports
}

# AI helpdesk settings (OpenAI-compatible API).
ai_api_base_url = ''
ai_api_key = ''
ai_model_name = ''

# Commands requiring user confirmation before AI executes.
ai_dangerous_commands = [
    # Destructive file/disk operations
    'rm', 'rmdir', 'shred', 'truncate',
    'mkfs', 'fdisk', 'parted', 'wipefs', 'dd',
    'lvremove', 'vgremove', 'pvremove',
    # Process/service/power control
    'kill', 'killall', 'pkill',
    'shutdown', 'reboot', 'poweroff', 'halt', 'init',
    'systemctl', 'service',
    # User/permission management
    'useradd', 'userdel', 'usermod',
    'passwd', 'chpasswd',
    'groupadd', 'groupdel', 'groupmod',
    'chown', 'chmod', 'visudo',
    # Network/firewall
    'iptables', 'ip6tables', 'nftables',
    'firewall-cmd', 'ufw',
    'ifdown', 'nmcli',
    # Package management
    'yum', 'dnf', 'apt', 'rpm', 'pip',
    # Scheduler state changes
    'bkill', 'badmin', 'bstop', 'bresume', 'brestart', 'bswitch',
    'scontrol', 'scancel',
    # Other risky operations
    'crontab', 'at',
    'mount', 'umount', 'fsck',
]
""")

            os.chmod(config_file, 0o600)
        except Exception as error:
            print('*Error*: Failed on opening config file "' + str(config_file) + '" for write: ' + str(error))
            sys.exit(1)


################
# Main Process #
################
def main():
    check_python_version()
    gen_batch_run()
    gen_shell_tools()
    gen_config_file()

    print('')
    print('Done, Please enjoy it.')


if __name__ == '__main__':
    main()
