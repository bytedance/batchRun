# -*- coding: utf-8 -*-
################################
# File Name   : cleanup_db.py
# Author      : liyanqing.1987
# Description : Cleanup expired history snapshots under db/ (host_stat, host_asset,
#               host_info, host_queue, ai_report). Intended to run as root via
#               crontab; does NOT touch db/log (use cleanup_log for that).
################################
import os
import sys
import time
import shutil
import argparse

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')

import config
import common

os.environ['PYTHONUNBUFFERED'] = '1'


# All cleanup targets. Each name maps to a db sub-directory (log is excluded, see cleanup_log).
ALL_TARGETS = ['host_stat', 'host_asset', 'host_info', 'host_queue', 'ai_report']

# File extensions/names that are NEVER deleted from any target directory, regardless of
# age. These are operational artifacts (scripts, logs, READMEs), not history snapshots.
# .enc / .master_key protect the encrypted secret store under db/host_asset (used by
# get_host_asset.py): the master key must never be cleaned or its ciphertext is lost.
PROTECTED_SUFFIXES = ('.sh', '.py', '.log', '.md', '.txt', '.list', '.enc', '.master_key')
PROTECTED_NAMES = {'readme', 'host.list', 'host_asset.json', 'host_asset.json.tmp', '.master_key', 'kingdee_secrets.enc'}


def read_args():
    parser = argparse.ArgumentParser(description='Cleanup expired history snapshots under db/ (run as root).')

    parser.add_argument('-d', '--days',
                        type=int,
                        default=None,
                        help='Override retention days for all targets (default: per-target config.history_retention_days).')
    parser.add_argument('-t', '--targets',
                        nargs='+',
                        default=ALL_TARGETS,
                        choices=ALL_TARGETS,
                        help='Specify target(s) to cleanup. Default: all. Choices: ' + ', '.join(ALL_TARGETS))
    parser.add_argument('--dry-run',
                        action='store_true',
                        default=False,
                        help='Preview mode, show what would be deleted without actually deleting.')

    return parser.parse_args()


def get_retention_days(target, override=None):
    """
    Get retention days for a target.
    Priority: CLI override > config.history_retention_days[target] > 30.
    """
    if override is not None:
        return override

    retention_map = getattr(config, 'history_retention_days', {})

    if isinstance(retention_map, dict) and target in retention_map:
        return retention_map[target]

    return 30


def collect_symlink_targets(base_dir, link_names):
    """
    Collect real paths pointed by symlinks under base_dir.
    These paths (and their parents while under base_dir) are protected from deletion.
    Returns a set of absolute real paths.
    """
    protected = set()

    for name in link_names:
        link_path = os.path.join(base_dir, name)

        if os.path.islink(link_path):
            try:
                real = os.path.realpath(link_path)

                if real:
                    protected.add(real)
            except OSError:
                pass

    return protected


def is_protected(path, protected_set):
    """
    Check if path itself or any of its parents is in protected_set.
    """
    try:
        abs_path = os.path.realpath(path)
    except OSError:
        abs_path = path

    while abs_path and abs_path != '/':
        if abs_path in protected_set:
            return True

        parent = os.path.dirname(abs_path)

        if parent == abs_path:
            break

        abs_path = parent

    return False


def is_operational_artifact(name):
    """
    True for scripts, logs, READMEs and other operational files that must never be
    cleaned up as history snapshots. Protects by suffix (.sh/.py/.log/...) and by
    exact name (case-insensitive) so e.g. get_host_asset.sh, get_host_asset.log,
    README are kept regardless of age.
    """
    if not name:
        return False

    if name.lower() in PROTECTED_NAMES:
        return True

    return name.lower().endswith(PROTECTED_SUFFIXES)


def delete_file(filepath, dry_run):
    """
    Delete a single file. Returns (count: int, size: int).
    In dry-run, returns (1, size) so the caller counts the planned deletion.
    """
    try:
        size = os.path.getsize(filepath)
    except OSError:
        size = 0

    if dry_run:
        print(f'  [dry-run] Would delete: {filepath} ({size / 1024 / 1024:.1f} MB)')
        return (1, size)

    try:
        os.remove(filepath)
        return (1, size)
    except OSError as e:
        common.bprint(f'Failed to delete "{filepath}": {e}', level='Warning')
        return (0, 0)


def delete_tree(path, dry_run):
    """
    Delete a directory tree. Returns (count: int, freed_bytes: int).
    Falls back to per-file removal on rmtree failure.
    """
    total_size = 0

    try:
        for root, dirs, files in os.walk(path):
            for f in files:
                try:
                    total_size += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except OSError:
        pass

    if dry_run:
        print(f'  [dry-run] Would delete dir: {path} ({total_size / 1024 / 1024:.1f} MB)')
        return (1, total_size)

    try:
        shutil.rmtree(path)
        return (1, total_size)
    except OSError as e:
        common.bprint(f'Failed to rmtree "{path}": {e}, retrying per-file ...', level='Warning')
        deleted = 0
        freed = 0

        for root, dirs, files in os.walk(path, topdown=False):
            for f in files:
                ok, size = delete_file(os.path.join(root, f), dry_run=False)
                deleted += ok
                freed += size

            for d in dirs:
                dp = os.path.join(root, d)

                try:
                    os.rmdir(dp)
                except OSError:
                    pass

        try:
            os.rmdir(path)
        except OSError:
            pass

        return (deleted, freed)


def scan_entries(base_dir):
    """
    Yield os.scandir entries under base_dir. Faster than os.listdir + stat on
    directories holding a large number of files (e.g. db/log/root).
    Returns None on OSError (caller reports).
    """
    try:
        entries = os.scandir(base_dir)
    except OSError as e:
        common.bprint(f'Failed to scan "{base_dir}": {e}', level='Warning')
        return None

    return entries


def cleanup_host_stat(days=7, dry_run=False):
    """
    Cleanup host_stat/<date>/<time>/ directories older than specified days.
    Deletes whole <date>/ sub-directories whose mtime < cutoff.
    Protects the host_stat.json symlink target.
    Returns (deleted_count, freed_bytes).
    """
    base_dir = str(config.db_path) + '/host_stat'

    if not os.path.exists(base_dir):
        return (0, 0)

    cutoff_time = time.time() - (days * 86400)
    protected = collect_symlink_targets(base_dir, ['host_stat.json', 'host_stat.json.tmp'])

    deleted_count = 0
    freed_bytes = 0

    entries = scan_entries(base_dir)

    if entries is None:
        return (0, 0)

    with entries:
        for entry in entries:
            if not entry.is_dir():
                continue

            date_dir = entry.path

            if is_protected(date_dir, protected):
                continue

            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue

            if mtime < cutoff_time:
                ok, size = delete_tree(date_dir, dry_run)
                deleted_count += ok
                freed_bytes += size

    return (deleted_count, freed_bytes)


def cleanup_host_asset(days=30, dry_run=False):
    """
    Cleanup host_asset snapshots older than specified days.
    Deletes timestamped snapshot files (assets_<date>_<time>.json; legacy
    kingdee_assets_by_ip_<date>_<time>.json are also covered since they are plain
    .json not matched by the protected-suffix/name whitelist).
    Keeps symlinks, scripts (*.sh/*.py), logs, READMEs, and the encrypted secret
    store (.enc / .master_key) used by get_host_asset.py.
    Returns (deleted_count, freed_bytes).
    """
    base_dir = str(config.db_path) + '/host_asset'

    if not os.path.exists(base_dir):
        return (0, 0)

    cutoff_time = time.time() - (days * 86400)
    protected = collect_symlink_targets(base_dir, ['host_asset.json', 'host_asset.json.tmp'])

    deleted_count = 0
    freed_bytes = 0

    entries = scan_entries(base_dir)

    if entries is None:
        return (0, 0)

    with entries:
        for entry in entries:
            if not entry.is_file() or entry.is_symlink():
                continue

            # Never delete operational artifacts (scripts, logs, READMEs).
            if is_operational_artifact(entry.name):
                continue

            if is_protected(entry.path, protected):
                continue

            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue

            if mtime < cutoff_time:
                ok, size = delete_file(entry.path, dry_run)
                deleted_count += ok
                freed_bytes += size

    return (deleted_count, freed_bytes)


def cleanup_host_info(days=30, dry_run=False):
    """
    Cleanup host_info timestamped snapshots older than specified days.
    Deletes host_info.json.<timestamp> files only; keeps *.info (per-host, overwritten).
    Returns (deleted_count, freed_bytes).
    """
    base_dir = str(config.db_path) + '/host_info'

    if not os.path.exists(base_dir):
        return (0, 0)

    cutoff_time = time.time() - (days * 86400)
    protected = collect_symlink_targets(base_dir, ['host_info.json', 'host_info.json.tmp'])

    deleted_count = 0
    freed_bytes = 0

    entries = scan_entries(base_dir)

    if entries is None:
        return (0, 0)

    with entries:
        for entry in entries:
            # Only touch host_info.json.<timestamp> snapshots; never touch *.info.
            if not entry.name.startswith('host_info.json.'):
                continue

            if entry.is_symlink():
                continue

            if not entry.is_file():
                continue

            if is_protected(entry.path, protected):
                continue

            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue

            if mtime < cutoff_time:
                ok, size = delete_file(entry.path, dry_run)
                deleted_count += ok
                freed_bytes += size

    return (deleted_count, freed_bytes)


def cleanup_host_queue(days=30, dry_run=False):
    """
    Cleanup host_queue timestamped snapshots older than specified days.
    Deletes host_queue.json.<timestamp> files only.
    Returns (deleted_count, freed_bytes).
    """
    base_dir = str(config.db_path) + '/host_queue'

    if not os.path.exists(base_dir):
        return (0, 0)

    cutoff_time = time.time() - (days * 86400)
    protected = collect_symlink_targets(base_dir, ['host_queue.json', 'host_queue.json.tmp'])

    deleted_count = 0
    freed_bytes = 0

    entries = scan_entries(base_dir)

    if entries is None:
        return (0, 0)

    with entries:
        for entry in entries:
            if not entry.name.startswith('host_queue.json.'):
                continue

            if entry.is_symlink():
                continue

            if not entry.is_file():
                continue

            if is_protected(entry.path, protected):
                continue

            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue

            if mtime < cutoff_time:
                ok, size = delete_file(entry.path, dry_run)
                deleted_count += ok
                freed_bytes += size

    return (deleted_count, freed_bytes)


def cleanup_ai_report(days=30, dry_run=False):
    """
    Cleanup ai_report HTML reports older than specified days.
    Deletes *_analysis_<timestamp>.html files.
    Returns (deleted_count, freed_bytes).
    """
    base_dir = str(config.db_path) + '/ai_report'

    if not os.path.exists(base_dir):
        return (0, 0)

    cutoff_time = time.time() - (days * 86400)

    deleted_count = 0
    freed_bytes = 0

    entries = scan_entries(base_dir)

    if entries is None:
        return (0, 0)

    with entries:
        for entry in entries:
            if not entry.name.endswith('.html'):
                continue

            if not entry.is_file():
                continue

            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue

            if mtime < cutoff_time:
                ok, size = delete_file(entry.path, dry_run)
                deleted_count += ok
                freed_bytes += size

    return (deleted_count, freed_bytes)


# Dispatch table: target name -> cleanup function.
TARGET_FUNCS = {
    'host_stat': cleanup_host_stat,
    'host_asset': cleanup_host_asset,
    'host_info': cleanup_host_info,
    'host_queue': cleanup_host_queue,
    'ai_report': cleanup_ai_report,
}


def run_cleanup(targets, days_override=None, dry_run=False):
    """
    Run cleanup for each target. Returns aggregated (deleted_count, freed_bytes).
    """
    total_deleted = 0
    total_freed = 0

    for target in targets:
        func = TARGET_FUNCS[target]
        retention = get_retention_days(target, days_override)
        base_dir = str(config.db_path) + '/' + target

        common.bprint(f'>>> Target "{target}"')

        if not os.path.isdir(base_dir):
            common.bprint(f'    Directory : {base_dir} (not found, skipped)', indent=4)
            continue

        common.bprint(f'    Directory : {base_dir}', indent=4)
        common.bprint(f'    Retention : {retention} days (delete items older than {retention} days)', indent=4)

        deleted, freed = func(days=retention, dry_run=dry_run)

        freed_mb = freed / 1024 / 1024

        if dry_run:
            common.bprint(f'    Result    : would delete {deleted} item(s), free {freed_mb:.1f} MB', indent=4)
        else:
            common.bprint(f'    Result    : deleted {deleted} item(s), freed {freed_mb:.1f} MB', indent=4)

        total_deleted += deleted
        total_freed += freed

    return (total_deleted, total_freed)


def main():
    args = read_args()

    common.bprint(f'Cleaning up history snapshots (targets: {", ".join(args.targets)}) ...')

    if args.dry_run:
        common.bprint('[DRY-RUN MODE] No files will be deleted.')

    total_deleted, total_freed = run_cleanup(
        targets=args.targets,
        days_override=args.days,
        dry_run=args.dry_run
    )

    freed_mb = total_freed / 1024 / 1024

    if args.dry_run:
        common.bprint(f'Dry-run complete. Would delete {total_deleted} item(s), free {freed_mb:.1f} MB in total.')
        common.bprint('Use without --dry-run to actually delete.')
    else:
        common.bprint(f'Done. Deleted {total_deleted} item(s), freed {freed_mb:.1f} MB in total.')


if __name__ == '__main__':
    main()
