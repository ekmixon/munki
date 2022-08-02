# encoding: utf-8
#
# Copyright 2009-2021 Greg Neagle.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
processes.py

Created by Greg Neagle on 2016-12-14.


Functions for finding, listing, etc processes
"""
from __future__ import absolute_import, print_function

import os
import signal
import subprocess

from .constants import LOGINWINDOW
from . import display


def get_running_processes():
    """Returns a list of paths of running processes"""
    proc = subprocess.Popen(['/bin/ps', '-axo' 'comm='],
                            shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    output = proc.communicate()[0].decode('UTF-8')
    if proc.returncode != 0:
        return []
    proc_list = [item for item in output.splitlines()
                 if item.startswith('/')]
    launchcfmapp = ('/System/Library/Frameworks/Carbon.framework'
                    '/Versions/A/Support/LaunchCFMApp')
    if launchcfmapp in proc_list:
        # we have a really old Carbon app
        proc = subprocess.Popen(['/bin/ps', '-axwwwo' 'args='],
                                shell=False, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        output = proc.communicate()[0].decode('UTF-8')
        if proc.returncode == 0:
            if carbon_apps := [
                item[len(launchcfmapp) + 1 :]
                for item in output.splitlines()
                if item.startswith(launchcfmapp)
            ]:
                proc_list.extend(carbon_apps)
    return proc_list


def is_app_running(appname):
    """Tries to determine if the application in appname is currently
    running"""
    display.display_detail(f'Checking if {appname} is running...')
    proc_list = get_running_processes()
    matching_items = []
    if appname.startswith('/'):
        # search by exact path
        matching_items = [item for item in proc_list
                          if item == appname]
    elif appname.endswith('.app'):
        # search by filename
        matching_items = [
            item for item in proc_list if f'/{appname}/Contents/MacOS/' in item
        ]

    else:
        # check executable name
        matching_items = [item for item in proc_list if item.endswith(f'/{appname}')]
    if not matching_items:
        # try adding '.app' to the name and check again
        matching_items = [
            item
            for item in proc_list
            if f'/{appname}.app/Contents/MacOS/' in item
        ]


    if matching_items:
        # it's running!
        display.display_debug1(f'Matching process list: {matching_items}')
        display.display_detail(f'{appname} is running!')
        return True

    # if we get here, we have no evidence that appname is running
    return False


def blocking_applications_running(pkginfoitem):
    """Returns true if any application in the blocking_applications list
    is running or, if there is no blocking_applications list, if any
    application in the installs list is running."""

    if 'blocking_applications' in pkginfoitem:
        appnames = pkginfoitem['blocking_applications']
    else:
        # if no blocking_applications specified, get appnames
        # from 'installs' list if it exists
        appnames = [os.path.basename(item.get('path'))
                    for item in pkginfoitem.get('installs', [])
                    if item.get('type') == 'application']

    display.display_debug1(f"Checking for {appnames}")
    if running_apps := [
        appname for appname in appnames if is_app_running(appname)
    ]:
        display.display_detail(f"Blocking apps for {pkginfoitem['name']} are running:")
        display.display_detail(f"    {running_apps}")
        return True
    return False


def find_processes(user=None, exe=None):
    """Find processes in process list.

    Args:
        user: str, optional, username owning process
        exe: str, optional, executable name of process
    Returns:
        dictionary of pids = {
                pid: {
                        'user': str, username owning process,
                        'exe': str, string executable of process,
                }
        }

        list of pids, or {} if none
    """
    argv = ['/bin/ps', '-x', '-w', '-w', '-a', '-o', 'pid=,user=,comm=']
    ps_proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = ps_proc.communicate()[0].decode('UTF-8')

    pids = {}

    if not stdout or ps_proc.returncode != 0:
        return pids

    try:
        lines = stdout.splitlines()
        for proc in lines:
            (p_pid, p_user, p_comm) = proc.split(None, 2)

            if exe is not None and not p_comm.startswith(exe):
                continue
            if user is not None and p_user != user:
                continue
            pids[int(p_pid)] = {
                'user': p_user,
                'exe': p_comm,
            }

    except (ValueError, TypeError, IndexError):
        return pids

    return pids


def force_logout_now():
    """Force the logout of interactive GUI users and spawn MSU."""
    try:
        procs = find_processes(exe=LOGINWINDOW)
        users = {procs[pid]['user']: pid for pid in procs}
        if 'root' in users:
            del users['root']

        # force MSU GUI to raise
        fileref = open('/private/tmp/com.googlecode.munki.installatlogout', 'w')
        fileref.close()

        # kill loginwindows to cause logout of current users, whether
        # active or switched away via fast user switching.
        for user, value in users.items():
            try:
                os.kill(value, signal.SIGKILL)
            except OSError:
                pass

    except BaseException as err:
        display.display_error(f'Exception in force_logout_now(): {str(err)}')


# this function is maybe an odd fit for this module, but it's a way for the
# Managed Software Center.app and MunkiStatus.app processes to tell the
# managedsoftwareupdate process to stop/cancel, so here it is!
_STOP_REQUESTED = False
def stop_requested():
    """Allows user to cancel operations when GUI status is being used"""
    global _STOP_REQUESTED
    if _STOP_REQUESTED:
        return True
    stop_request_flag = (
        '/private/tmp/'
        'com.googlecode.munki.managedsoftwareupdate.stop_requested')
    if os.path.exists(stop_request_flag):
        # store this so it's persistent until this session is over
        _STOP_REQUESTED = True
        display.display_info('### User stopped session ###')
        try:
            os.unlink(stop_request_flag)
        except OSError as err:
            display.display_error(
                'Could not remove %s: %s', stop_request_flag, err)
        return True
    return False


if __name__ == '__main__':
    print('This is a library of support tools for the Munki Suite.')
