import os
import sys
import time
import json
import argparse

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')

import config
import common


def read_args():
    parser = argparse.ArgumentParser(description='Cleanup expired log files under db/log/.')

    parser.add_argument('-d', '--days',
                        type=int,
                        default=getattr(config, 'log_retention_days', 30),
                        help='Delete log files older than specified days (default: config.log_retention_days or 30).')
    parser.add_argument('-u', '--users',
                        nargs='+',
                        default=[],
                        help='Only cleanup specified user(s). Default: all users.')
    parser.add_argument('--dry-run',
                        action='store_true',
                        default=False,
                        help='Preview mode, show what would be deleted without actually deleting.')

    return parser.parse_args()


def cleanup_log(days=30, users=None, dry_run=False):
    """
    Cleanup log files older than specified days.
    Returns (deleted_files_count, freed_bytes).
    """
    log_dir = str(config.db_path) + '/log'

    if not os.path.exists(log_dir):
        return (0, 0)

    cutoff_time = time.time() - (days * 86400)
    deleted_count = 0
    freed_bytes = 0

    if not users:
        users = [d for d in os.listdir(log_dir) if os.path.isdir(os.path.join(log_dir, d))]

    for user in users:
        user_dir = os.path.join(log_dir, user)

        if not os.path.isdir(user_dir):
            continue

        # Cleanup log output files (everything except command.his).
        try:
            dir_contents = os.listdir(user_dir)
        except PermissionError:
            continue

        for filename in dir_contents:
            if filename == 'command.his':
                continue

            filepath = os.path.join(user_dir, filename)

            if not os.path.isfile(filepath):
                continue

            try:
                mtime = os.path.getmtime(filepath)
            except OSError:
                continue

            if mtime < cutoff_time:
                file_size = os.path.getsize(filepath)

                if dry_run:
                    print(f'  [dry-run] Would delete: {filepath} ({file_size / 1024 / 1024:.1f} MB)')
                else:
                    try:
                        os.remove(filepath)
                        deleted_count += 1
                        freed_bytes += file_size
                    except OSError as e:
                        common.bprint(f'Failed to delete "{filepath}": {e}', level='Warning')

        # Trim command.his: remove entries older than cutoff.
        command_his_file = os.path.join(user_dir, 'command.his')

        if os.path.exists(command_his_file):
            try:
                with open(command_his_file, 'r') as f:
                    lines = f.readlines()

                original_count = len(lines)
                kept_lines = []

                for line in lines:
                    try:
                        record = json.loads(line)
                        record_date = record.get('date', '')

                        if record_date:
                            record_time = time.mktime(time.strptime(record_date, '%Y%m%d'))

                            if record_time >= cutoff_time:
                                kept_lines.append(line)
                        else:
                            kept_lines.append(line)
                    except (json.JSONDecodeError, ValueError):
                        kept_lines.append(line)

                trimmed_count = original_count - len(kept_lines)

                if trimmed_count > 0:
                    if dry_run:
                        print(f'  [dry-run] Would trim {trimmed_count} entries from {command_his_file}')
                    else:
                        with open(command_his_file, 'w') as f:
                            f.writelines(kept_lines)

                        common.bprint(f'Trimmed {trimmed_count} expired entries from {command_his_file}.')
            except OSError as e:
                common.bprint(f'Failed to process "{command_his_file}": {e}', level='Warning')

    return (deleted_count, freed_bytes)


def main():
    args = read_args()

    common.bprint(f'Cleaning up log files older than {args.days} days ...')

    if args.dry_run:
        common.bprint('[DRY-RUN MODE] No files will be deleted.')

    deleted_count, freed_bytes = cleanup_log(
        days=args.days,
        users=args.users if args.users else None,
        dry_run=args.dry_run
    )

    if args.dry_run:
        common.bprint('Dry-run complete. Use without --dry-run to actually delete.')
    else:
        freed_mb = freed_bytes / 1024 / 1024
        common.bprint(f'Done. Deleted {deleted_count} files, freed {freed_mb:.1f} MB.')


if __name__ == '__main__':
    main()
