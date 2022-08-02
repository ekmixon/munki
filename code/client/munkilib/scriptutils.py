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
scriptutils.py

Created by Greg Neagle on 2016-12-14.


Functions to run scripts inside Munki
"""
from __future__ import absolute_import, print_function

import os
import subprocess

from . import osutils
from . import display
from . import munkilog
from . import munkistatus


def _writefile(stringdata, path):
    '''Writes string data to path.
    Returns the path on success, empty string on failure.'''
    try:
        with open(path, mode='wb') as fileobject:
            # write line-by-line to ensure proper UNIX line-endings
            for line in stringdata.splitlines():
                fileobject.write(line.encode('UTF-8') + b"\n")
        return path
    except (OSError, IOError):
        display.display_error("Couldn't write %s" % stringdata)
        return ""


def run_embedded_script(scriptname, pkginfo_item, suppress_error=False):
    '''Runs a script embedded in the pkginfo.
    Returns the result code.'''

    # get the script text from the pkginfo
    script_text = pkginfo_item.get(scriptname)
    itemname = pkginfo_item.get('name')
    if not script_text:
        display.display_error(f'Missing script {scriptname} for {itemname}')
        return -1

    # write the script to a temp file
    scriptpath = os.path.join(osutils.tmpdir(), scriptname)
    if _writefile(script_text, scriptpath):
        cmd = ['/bin/chmod', '-R', 'o+x', scriptpath]
        if retcode := subprocess.call(cmd):
            display.display_error(
                f'Error setting script mode in {scriptname} for {itemname}'
            )

            return -1
    else:
        display.display_error(f'Cannot write script {scriptname} for {itemname}')
        return -1

    # now run the script
    return run_script(
        itemname, scriptpath, scriptname, suppress_error=suppress_error)


def run_script(itemname, path, scriptname, suppress_error=False):
    '''Runs a script, Returns return code.'''
    if suppress_error:
        display.display_detail(f'Running {scriptname} for {itemname} ')
    else:
        display.display_status_minor(f'Running {scriptname} for {itemname} ')
    if display.munkistatusoutput:
        # set indeterminate progress bar
        munkistatus.percent(-1)

    scriptoutput = []
    try:
        proc = subprocess.Popen(path, shell=False,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
    except OSError as err:
        display.display_error(f'Error executing script {scriptname}: {str(err)}')
        return -1

    while True:
        msg = proc.stdout.readline().decode('UTF-8')
        if not msg and (proc.poll() != None):
            break
        # save all script output in case there is
        # an error so we can dump it to the log
        scriptoutput.append(msg)
        msg = msg.rstrip("\n")
        display.display_info(msg)

    retcode = proc.poll()
    if retcode and not suppress_error:
        display.display_error(f'Running {scriptname} for {itemname} failed.')
        display.display_error("-"*78)
        for line in scriptoutput:
            display.display_error("\t%s" % line.rstrip("\n"))
        display.display_error("-"*78)
    elif not suppress_error:
        munkilog.log(f'Running {scriptname} for {itemname} was successful.')

    if display.munkistatusoutput:
        # clear indeterminate progress bar
        munkistatus.percent(0)

    return retcode


if __name__ == '__main__':
    print('This is a library of support tools for the Munki Suite.')
