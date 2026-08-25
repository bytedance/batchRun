import os
import re
import sys
import time
import hmac
import base64
import getpass
import hashlib
import subprocess

import pexpect

try:
    from cryptography.fernet import Fernet, InvalidToken
    _HAS_FERNET = True
except Exception:
    _HAS_FERNET = False

try:
    import common_secure_key
    _HAS_LEGACY = True
except Exception:
    _HAS_LEGACY = False

VERSION = '2026.08.02'

# Field separator used in the password file (two spaces, kept for backward compat).
_FIELD_SEP = '  '


def _run_capture(command_list, timeout=5):
    """Run a command without shell and return its stripped stdout (empty string on any error)."""
    try:
        result = subprocess.run(command_list, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout, universal_newlines=True)
        return (result.stdout or '').strip()
    except Exception:
        return ''


def _looks_like_fernet_token(value):
    """A Fernet token is urlsafe-base64 and starts with the version byte 0x80 -> 'gAAAA'."""
    if not value or not value.startswith('gAAAA'):
        return False

    if not re.match(r'^[A-Za-z0-9_\-=]+$', value):
        return False

    return True


class SaveAndGetPassword():
    """
    Password storage with a separate master key.

    Security model:
      * A master key is generated once and stored in a 0o600 file next to the
        password directory. It is NEVER stored together with the ciphertext.
      * Passwords are encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
      * Integrity is protected with HMAC-SHA256 keyed by the master key.
      * Legacy entries produced by the old common_secure_key.so (AES-CBC with a
        key derived from the plaintext user/host/second fields) can still be
        decrypted on read for migration. New writes always use Fernet.
    """

    def __init__(self, debug=False, master_key_path=None):
        self.debug = debug
        self._master_key_path = master_key_path
        self._fernet = None
        # HMAC signing key derived once from the master key (first 16 bytes of the
        # urlsafe-base64-decoded Fernet key). Cached here so MAC computation does
        # not depend on Fernet's private ``_signing_key`` attribute.
        self._signing_key = None

        if not _HAS_FERNET:
            self.debug_print('*Warning*: cryptography.Fernet unavailable, new passwords cannot be encrypted.')

    def debug_print(self, message):
        if self.debug:
            print(message)

    # ------------------------------------------------------------------ key
    def _get_master_key_path(self, password_file):
        if self._master_key_path:
            return self._master_key_path

        return os.path.join(os.path.dirname(os.path.abspath(password_file)), '.master_key')

    def _load_master_key(self, password_file):
        """Load (or create) the Fernet master key. Returns a Fernet instance or None."""
        if not _HAS_FERNET:
            return None

        if self._fernet is not None:
            return self._fernet

        key_file = self._get_master_key_path(password_file)

        try:
            if os.path.exists(key_file):
                with open(key_file, 'rb') as KF:
                    key = KF.read().strip()

                if key:
                    self._fernet = Fernet(key)
                    self._signing_key = base64.urlsafe_b64decode(key)[:16]

                    return self._fernet

            # generate a new key
            key = Fernet.generate_key()
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

            try:
                os.write(fd, key)
            finally:
                os.close(fd)

            self._fernet = Fernet(key)
            self._signing_key = base64.urlsafe_b64decode(key)[:16]

            return self._fernet
        except Exception as error:
            self.debug_print('*Error*: Failed on master key "' + str(key_file) + '": ' + str(error))
            return None

    def _encrypt(self, plaintext, password_file):
        f = self._load_master_key(password_file)

        if f is None:
            return None

        try:
            return f.encrypt(plaintext.encode('utf-8')).decode('ascii')
        except Exception as error:
            self.debug_print('*Error*: encrypt failed: ' + str(error))
            return None

    def _decrypt_new(self, token, password_file):
        f = self._load_master_key(password_file)

        if f is None:
            return None

        try:
            return f.decrypt(token.encode('ascii')).decode('utf-8')
        except InvalidToken:
            return None
        except Exception:
            return None

    @staticmethod
    def _decrypt_legacy(user, host, second, token):
        if not _HAS_LEGACY:
            return None

        try:
            return common_secure_key.decrypt_password(user, host, second, token)
        except Exception:
            return None

    # ------------------------------------------------------------------ parse
    def __parse_password_file(self, password_file):
        """
        Line format: <user>  <host>  <second>  <password>  <mac>
        New entries: <password> is a Fernet token, <mac> is HMAC-SHA256 hex.
        Legacy entries: <password> is hex (old .so), <mac> is MD5 hex.
        """
        password_dic = {}

        if os.path.exists(password_file):
            try:
                with open(password_file, 'r') as PF:
                    for line in PF.readlines():
                        my_match = re.match(r'^(\S+)  (\S+)  (\d+)  (\S+)  (\S+)$', line)

                        if not my_match:
                            continue

                        user = my_match.group(1)
                        host = my_match.group(2)
                        second = my_match.group(3)
                        password = my_match.group(4)
                        mac = my_match.group(5)
                        key_info = str(user) + str(host) + str(second) + str(password)

                        if _looks_like_fernet_token(password):
                            f = self._load_master_key(password_file)

                            if f is not None:
                                expected = hmac.new(self._signing_key, key_info.encode('utf-8'),
                                                    hashlib.sha256).hexdigest()
                            else:
                                expected = ''

                            if not hmac.compare_digest(expected, mac):
                                # Tampered/corrupt new entry -> drop the file.
                                try:
                                    os.remove(password_file)
                                except Exception as error:
                                    self.debug_print('*Error*: Failed on removing file "' + str(password_file) + '": ' + str(error))

                                return password_dic
                        else:
                            # Legacy integrity (MD5). Keep for compatibility.
                            check_md5 = hashlib.md5(key_info.encode()).hexdigest()

                            if check_md5 != mac:
                                try:
                                    os.remove(password_file)
                                except Exception as error:
                                    self.debug_print('*Error*: Failed on removing file "' + str(password_file) + '": ' + str(error))

                                return password_dic

                        password_dic.setdefault(user, {})

                        if host not in password_dic[user]:
                            password_dic[user][host] = {'second': second, 'password': password}
                        else:
                            self.debug_print('*Warning*: Repeated user/host setting on password file for below line, ignore.')
                            self.debug_print('           ' + str(line.strip()))
            except Exception as error:
                self.debug_print('*Error*: Failed on opening file "' + str(password_file) + '" for read, ' + str(error))

        return password_dic

    # ------------------------------------------------------------------ permission
    def __check_user_permission(self, user, mode):
        """
        Permission check passes only when the specified user matches the real
        (login) user and the current user. In a non-interactive session where
        'who am i' is empty, we fall back to current_user equality.
        """
        who = _run_capture(['who', 'am', 'i'])
        login_user = who.split()[0] if who else ''
        current_user = _run_capture(['whoami'])

        if (user == current_user == login_user) or ((user == current_user) and (login_user == '')):
            return True
        else:
            self.debug_print('*Error*: ' + str(mode) + ' password fail, make sure login_user/current_user/specified_user are the same.')
            return False

    # ------------------------------------------------------------------ public
    def save_password(self, password_file, password, user='', host='default'):
        if not user:
            user = getpass.getuser()

        if not self.__check_user_permission(user, 'save'):
            return

        f = self._load_master_key(password_file)

        if f is None:
            self.debug_print('*Error*: master key unavailable, cannot save password.')
            return

        password_dic = self.__parse_password_file(password_file)

        if user not in password_dic:
            password_dic.setdefault(user, {})

        current_second = str(int(time.time()))
        encrypted_password = self._encrypt(password, password_file)

        if encrypted_password is None:
            self.debug_print('*Error*: encrypt failed, password not saved.')
            return

        password_dic[user][host] = {'second': current_second, 'password': encrypted_password}

        try:
            # Write atomically: temp file + rename, then tighten perms.
            tmp_file = str(password_file) + '.tmp'

            with open(tmp_file, 'w') as PF:
                for u in password_dic.keys():
                    for h in password_dic[u].keys():
                        second = password_dic[u][h]['second']
                        pw = password_dic[u][h]['password']
                        key_info = str(u) + str(h) + str(second) + str(pw)
                        mac = hmac.new(self._signing_key, key_info.encode('utf-8'), hashlib.sha256).hexdigest()
                        PF.write(_FIELD_SEP.join([str(u), str(h), str(second), str(pw), str(mac)]) + '\n')

            os.chmod(tmp_file, 0o600)
            os.replace(tmp_file, password_file)
            os.chmod(password_file, 0o600)
        except Exception as error:
            self.debug_print('*Error*: Failed on opening file "' + str(password_file) + '" for write, ' + str(error))

    def get_password(self, password_file, user='', host='default'):
        decrypted_password = ''

        if not user:
            user = getpass.getuser()

        if not self.__check_user_permission(user, 'get'):
            return ''

        password_dic = self.__parse_password_file(password_file)

        if user not in password_dic:
            self.debug_print('*Error*: Not find password information for user "' + str(user) + '" on password file "' + str(password_file) + '".')
        else:
            if host not in password_dic[user]:
                host = 'default'

            entry = password_dic[user][host]
            second = entry['second']
            token = entry['password']

            if _looks_like_fernet_token(token):
                plaintext = self._decrypt_new(token, password_file)
            else:
                # Legacy .so entry: decrypt on the fly (no rewrite, lower risk).
                plaintext = self._decrypt_legacy(user, host, second, token)

            if plaintext is not None:
                decrypted_password = plaintext

        return decrypted_password


def get_password(user, host, password):
    """
    Resolve a password from (in priority order):
      1. an already-provided password;
      2. the BATCH_RUN_PASSWORD environment variable (kept out of argv/ps);
      3. the on-disk encrypted password store.
    """
    if not password:
        password = os.environ.get('BATCH_RUN_PASSWORD', '')

    if not password:
        if 'BATCH_RUN_INSTALL_PATH' in os.environ:
            sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')

            try:
                import config
            except Exception:
                config = None

            if config is not None:
                password_file = str(config.db_path) + '/password/' + str(user)

                if os.path.exists(password_file):
                    my_save_and_get_password = SaveAndGetPassword()
                    password = my_save_and_get_password.get_password(password_file, user, host)

    return password


def login_run(run_command, user, host, password, timeout=10):
    """
    For the scenarios that require logging into the server with a user/password to run.
    Typical scenarios are "ssh" and "scp".
    """
    # Retry refused/empty connections a few times. Under high parallelism the
    # remote sshd or local socket layer intermittently refuses or drops a
    # connection before the password prompt -- pexpect then sees EOF with empty
    # `before`, which looks like "no output" rather than a failure.
    #
    # Default is a SINGLE attempt: batch_run.parallel_run already has a
    # batch-level retry_failed_hosts fallback that reruns empty-output hosts at
    # lower concurrency, so an immediate per-host retry only makes genuinely
    # dead hosts pay extra pexpect timeouts (a 1000-host batch with hundreds of
    # dead hosts otherwise stalls for tens of minutes). Set
    # config.ssh_login_attempts (>=2) to restore the immediate retry for
    # interactive / low-concurrency runs without --output_file.
    max_attempts = 1

    try:
        if 'BATCH_RUN_INSTALL_PATH' in os.environ:
            sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
            import config
            max_attempts = int(getattr(config, 'ssh_login_attempts', 1))
    except Exception:
        pass

    if max_attempts < 1:
        max_attempts = 1

    last_result = []

    for attempt in range(1, max_attempts + 1):
        stdout_list, was_exception = _login_run_once(run_command, user, host, password, timeout)
        last_result = stdout_list

        # A non-empty result that did not come from an exception is a real
        # success -> stop retrying.
        if stdout_list and not was_exception:
            break

        # Empty result OR an exception (e.g. pexpect TIMEOUT): retry, since
        # under parallelism both are usually transient connection failures.
        if attempt < max_attempts:
            time.sleep(0.5 * attempt)

    return last_result


def _login_run_once(run_command, user, host, password, timeout=10):
    """Single ssh/scp attempt. Returns (stdout_lines, was_exception).
    was_exception is True when the result is an exception message rather than
    real command output, so the caller can keep retrying."""
    stdout_list = []
    was_exception = False
    child = None

    try:
        # use_poll=True: pexpect then waits on select.poll() instead of
        # select.select(). select() is capped at FD_SETSIZE=1024, so once the
        # process has ~1024 open fds (which happens quickly with hundreds of
        # parallel ssh sessions, each holding several fds) every later
        # expect()/read() raises "filedescriptor out of range in select()" and
        # the host silently gets empty output. poll() has no such cap.
        child = pexpect.spawn(run_command, timeout=timeout, use_poll=True)
        expect_list = ['assword:', pexpect.EOF]
        index = child.expect(expect_list)

        if index == 0:
            password = get_password(user, host, password)
            child.sendline(password)
            stdout = child.read()
        else:
            stdout = child.before

        if stdout:
            try:
                stdout_list = str(stdout, 'utf-8').strip().split('\n')
            except UnicodeDecodeError:
                stdout_list = str(stdout, 'utf-8', 'replace').strip().split('\n')
    except Exception as warning:
        # Surface the exception as the result (keeps it visible to callers),
        # but mark it so login_run retries instead of treating it as success.
        stdout_list = str(warning).split('\n')
        was_exception = True
    finally:
        # Always release the spawned ssh/scp process, even on timeout/error,
        # to avoid orphan processes and leaked remote connections.
        if child is not None:
            try:
                child.close(force=True)
            except Exception:
                pass

    return stdout_list, was_exception


def ssh_run(ssh_command, user, host, password, timeout=10):
    stdout_list = login_run(ssh_command, user, host, password, timeout)
    return stdout_list


def scp_run(scp_command, user, host, password, timeout=10):
    stdout_list = login_run(scp_command, user, host, password, timeout)
    return stdout_list
