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
    """
    python_lib_path = re.sub('/bin', '/lib', PYTHON_PATH)
    ld_library_path_setting = 'export LD_LIBRARY_PATH=$BATCH_RUN_INSTALL_PATH/lib:' + str(python_lib_path) + ':'

    if 'LD_LIBRARY_PATH' in os.environ:
        if python_lib_path in str(os.environ['LD_LIBRARY_PATH']):
            ld_library_path_setting = str(ld_library_path_setting) + re.sub(str(python_lib_path) + ':', '', os.environ['LD_LIBRARY_PATH'])
        else:
            ld_library_path_setting = str(ld_library_path_setting) + str(os.environ['LD_LIBRARY_PATH'])

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

# Preprocess "command" argument.
pre_arg=""
num=-1

for arg in "$@"
do
    if [[ $pre_arg == "-c" ]] || [[ $pre_arg == "--command" ]]; then
        if [[ $arg =~ " " ]] && [[ $arg =~ "-" ]]; then
            arg=`echo $arg | sed 's/-/\\\\\\-/g'`
        fi
    fi

    num=$(($num+1))
    args[$num]=$arg
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
    tool_list = ['bin/batch_run_gui', 'tools/encrypt_python', 'tools/patch', 'tools/sample_host_info', 'tools/save_password', 'tools/switch_etc_hosts']
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
python3 $BATCH_RUN_INSTALL_PATH/""" + str(tool_name) + '.py $@')

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
default_ssh_command = "ssh -o StrictHostKeyChecking=no -t -q"

# Support host_ip fuzzy matching, could be "True" or "False".
fuzzy_match = True

# Define timeout for ssh command, unit is "second".
serial_timeout = 10
parallel_timeout = 100
""")

            os.chmod(config_file, 0o777)
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
