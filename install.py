import os
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
    required_python = (3, 8)

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


def gen_env_file():
    env_file = str(CWD) + '/.env.py'

    try:
        with open(env_file, 'w') as EF:
            EF.write("""
# Set python3 path.
PYTHON_PATH = """ + str(PYTHON_PATH) + """

# Set install path.
BATCH_RUN_INSTALL_PATH = """ + str(CWD))
    except Exception as error:
        print('*Error*: Failed on writting env file "' + str(env_file) + '".')
        print('         ' + str(error))
        sys.exit(1)


def gen_batch_run():
    """
    Generate script <BATCH_RUN_INSTALL_PATH>/bin/batch_run.
    """
    batch_run = str(CWD) + '/bin/batch_run'

    print('')
    print('>>> Generate script "' + str(batch_run) + '".')

    try:
        with open(batch_run, 'w') as BR:
            BR.write("""#!/bin/bash

# Set python3 path.
export PATH=""" + str(PYTHON_PATH) + """:$PATH

# Set install path.
export BATCH_RUN_INSTALL_PATH=""" + str(CWD) + """

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
    Generate shell scripts under <BATCH_RUN_INSTALL_PATH>/tools.
    """
    tool_list = ['tools/encrypt_python', 'tools/patch', 'tools/sample_host_info', 'tools/save_password', 'tools/switch_etc_hosts']

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
timeout = 10
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
    gen_env_file()
    gen_batch_run()
    gen_shell_tools()
    gen_config_file()

    print('')
    print('Done, Please enjoy it.')


if __name__ == '__main__':
    main()
