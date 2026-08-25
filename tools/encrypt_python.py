# -*- coding: utf-8 -*-
################################
# File Name   : encrypt_python.py
# Author      : liyanqing
# Created On  : 2021-08-17 09:08:33
# Description :
################################
import os
import re
import sys
import shutil
import argparse
import subprocess

os.environ['PYTHONUNBUFFERED'] = '1'


def read_args():
    """
    Read in arguments.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--python_files',
                        required=True,
                        nargs='+',
                        default=[],
                        help='Specify python files want to encrypt.')

    args = parser.parse_args()

    return args.python_files


def gen_setup_file(python_files):
    setup_file = str(os.getcwd()) + '/encrypt_python_setup.py'

    print('>>> Write setup file "' + str(setup_file) + '".')

    try:
        with open(setup_file, 'w') as EF:
            EF.write('import os\n')
            EF.write('from setuptools import setup\n')
            EF.write('from Cython.Build import cythonize\n')
            EF.write('\n')
            EF.write('python_files = [')

            for python_file in python_files:
                # Escape single quotes so a path containing one cannot break out
                # of the generated Python string literal.
                safe = str(python_file).replace('\\', '\\\\').replace("'", "\\'")
                EF.write("'" + safe + "', ")

            EF.write(']\n')
            EF.write("os.environ['CFLAGS']='-std=c99'\n")
            EF.write('\n')
            EF.write('setup(ext_modules = cythonize(python_files),)\n')
    except Exception as error:
        print('*Error*: Failed on open setup file "' + str(setup_file) + '" for write: ' + str(error))
        sys.exit(1)

    return setup_file


def execute_setup_file(setup_file):
    command = ['python3', str(setup_file), 'build_ext', '--inplace']

    print('>>> Executing setup file ...')
    print('    ' + str(' '.join(command)))

    try:
        subprocess.run(command, check=False)
    except Exception as error:
        print('*Error*: Failed on executing setup file: ' + str(error))


def cleanup_directory(python_files, setup_file):
    setup_file_name = re.sub(r'.*/', '', setup_file)

    for file_name in os.listdir(os.getcwd()):
        if file_name == setup_file_name:
            print('    rm -rf ' + str(setup_file))

            try:
                os.remove(setup_file)
            except OSError:
                pass
        elif (file_name == 'build') and os.path.isdir(file_name):
            print('    rm -rf ' + str(file_name))

            try:
                shutil.rmtree(file_name)
            except Exception as error:
                print('    *Error*: ' + str(error))
        elif re.match(r'^.*\.c$', file_name):
            for python_file in python_files:
                python_file_name = re.sub(r'\.py', '', python_file)

                if re.match(r'^' + re.escape(python_file_name) + r'\.c$', file_name):
                    print('    rm -rf ' + str(file_name))

                    try:
                        os.remove(file_name)
                    except OSError as error:
                        print('    *Error*: ' + str(error))

                    break
        elif re.match(r'^.*\.so$', file_name):
            for python_file in python_files:
                python_file_name = re.sub(r'\.py', '', python_file)

                if re.match(r'^' + re.escape(python_file_name) + r'.*\.so$', file_name):
                    target = str(python_file_name) + '.so'
                    print('    mv ' + str(file_name) + ' ' + str(target))

                    try:
                        shutil.move(file_name, target)
                    except Exception as error:
                        print('    *Error*: ' + str(error))

                    break


################
# Main Process #
################
def main():
    (python_files) = read_args()
    setup_file = gen_setup_file(python_files)
    execute_setup_file(setup_file)
    cleanup_directory(python_files, setup_file)


if __name__ == '__main__':
    main()
