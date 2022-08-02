# encoding: utf-8
#
# Copyright 2017-2021 Greg Neagle.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
munkiimportlib

Created by Greg Neagle on 2017-11-18.
Routines used by munkimport to import items into Munki repo
"""
from __future__ import absolute_import, print_function

# std lib imports
import os
import sys

# our lib imports
from .common import list_items_of_kind
from .. import iconutils
from .. import dmgutils
from .. import munkihash
from .. import munkirepo
from .. import osinstaller
from .. import osutils
from .. import pkgutils
from .. import FoundationPlist
from ..cliutils import pref


class RepoCopyError(Exception):
    '''Exception raised when copying a file to the repo fails'''
    pass


def copy_item_to_repo(repo, itempath, vers, subdirectory=''):
    """Copies an item to the appropriate place in the repo.
    If itempath is a path within the repo/pkgs directory, copies nothing.
    Renames the item if an item already exists with that name.
    Returns the relative path to the item."""

    destination_path = os.path.join('pkgs', subdirectory)
    item_name = os.path.basename(itempath)
    destination_path_name = os.path.join(destination_path, item_name)

    name, ext = os.path.splitext(item_name)
    if vers and not name.endswith(vers):
            # add the version number to the end of the filename
        item_name = f'{name}-{vers}{ext}'
        destination_path_name = os.path.join(destination_path, item_name)

    index = 0
    try:
        pkgs_list = list_items_of_kind(repo, 'pkgs')
    except munkirepo.RepoError as err:
        raise RepoCopyError(f'Unable to get list of current pkgs: {err}')
    while destination_path_name in pkgs_list:
        #print 'File %s already exists...' % destination_path_name
        # try appending numbers until we have a unique name
        index += 1
        item_name = f'{name}__{index}{ext}'
        destination_path_name = os.path.join(destination_path, item_name)

    try:
        repo.put_from_local_file(destination_path_name, itempath)
    except munkirepo.RepoError as err:
        raise RepoCopyError(
            f'Unable to copy {itempath} to {destination_path_name}: {err}'
        )

    else:
        return destination_path_name


def copy_pkginfo_to_repo(repo, pkginfo, subdirectory=''):
    """Saves pkginfo to <munki_repo>/pkgsinfo/subdirectory"""
    # less error checking because we copy the installer_item
    # first and bail if it fails...
    destination_path = os.path.join('pkgsinfo', subdirectory)
    pkginfo_ext = pref('pkginfo_extension') or ''
    if pkginfo_ext and not pkginfo_ext.startswith('.'):
        pkginfo_ext = f'.{pkginfo_ext}'
    pkginfo_name = f"{pkginfo['name']}-{pkginfo['version']}{pkginfo_ext}"
    pkginfo_path = os.path.join(destination_path, pkginfo_name)
    index = 0
    try:
        pkgsinfo_list = list_items_of_kind(repo, 'pkgsinfo')
    except munkirepo.RepoError as err:
        raise RepoCopyError(f'Unable to get list of current pkgsinfo: {err}')
    while pkginfo_path in pkgsinfo_list:
        index += 1
        pkginfo_name = f"{pkginfo['name']}-{pkginfo['version']}__{index}{pkginfo_ext}"
        pkginfo_path = os.path.join(destination_path, pkginfo_name)

    try:
        pkginfo_str = FoundationPlist.writePlistToString(pkginfo)
    except FoundationPlist.NSPropertyListWriteException as errmsg:
        raise RepoCopyError(errmsg)
    try:
        repo.put(pkginfo_path, pkginfo_str)
        return pkginfo_path
    except munkirepo.RepoError as err:
        raise RepoCopyError(f'Unable to save pkginfo to {pkginfo_path}: {err}')


class CatalogDBException(Exception):
    '''Exception to throw if we can't make a pkginfo DB'''
    pass


class CatalogReadException(CatalogDBException):
    '''Exception to throw if we can't read the all catalog'''
    pass


class CatalogDecodeException(CatalogDBException):
    '''Exception to throw if we can't decode the all catalog'''
    pass


def make_catalog_db(repo):
    """Returns a dict we can use like a database"""

    try:
        plist = repo.get('catalogs/all')
    except munkirepo.RepoError as err:
        raise CatalogReadException(err)

    try:
        catalogitems = FoundationPlist.readPlistFromString(plist)
    except FoundationPlist.NSPropertyListSerializationException as err:
        raise CatalogDecodeException(err)

    pkgid_table = {}
    app_table = {}
    installer_item_table = {}
    hash_table = {}
    profile_table = {}

    itemindex = -1
    for item in catalogitems:
        itemindex = itemindex + 1
        name = item.get('name', 'NO NAME')
        vers = item.get('version', 'NO VERSION')

        if name == 'NO NAME' or vers == 'NO VERSION':
            print(f'WARNING: Bad pkginfo: {item}', file=sys.stderr)

        # add to hash table
        if 'installer_item_hash' in item:
            if item['installer_item_hash'] not in hash_table:
                hash_table[item['installer_item_hash']] = []
            hash_table[item['installer_item_hash']].append(itemindex)

        # add to installer item table
        if 'installer_item_location' in item:
            installer_item_name = os.path.basename(
                item['installer_item_location'])
            (name, ext) = os.path.splitext(installer_item_name)
            if '-' in name:
                (name, vers) = pkgutils.nameAndVersion(name)
            installer_item_name = name + ext
            if installer_item_name not in installer_item_table:
                installer_item_table[installer_item_name] = {}
            if vers not in installer_item_table[installer_item_name]:
                installer_item_table[installer_item_name][vers] = []
            installer_item_table[installer_item_name][vers].append(itemindex)

        # add to table of receipts
        for receipt in item.get('receipts', []):
            try:
                if 'packageid' in receipt and 'version' in receipt:
                    pkgid = receipt['packageid']
                    pkgvers = receipt['version']
                    if pkgid not in pkgid_table:
                        pkgid_table[pkgid] = {}
                    if pkgvers not in pkgid_table[pkgid]:
                        pkgid_table[pkgid][pkgvers] = []
                    pkgid_table[pkgid][pkgvers].append(itemindex)
            except TypeError:
                print(f'Bad receipt data for {name}-{vers}: {receipt}', file=sys.stderr)

        # add to table of installed applications
        for install in item.get('installs', []):
            try:
                if install.get('type') == 'application' and 'path' in install:
                    if install['path'] not in app_table:
                        app_table[install['path']] = {}
                    if vers not in app_table[install['path']]:
                        app_table[install['path']][vers] = []
                    app_table[install['path']][vers].append(itemindex)
            except TypeError:
                print(f'Bad install data for {name}-{vers}: {install}', file=sys.stderr)

        # add to table of PayloadIdentifiers
        if 'PayloadIdentifier' in item:
            if item['PayloadIdentifier'] not in profile_table:
                profile_table[item['PayloadIdentifier']] = {}
            if vers not in profile_table[item['PayloadIdentifier']]:
                profile_table[item['PayloadIdentifier']][vers] = []
            profile_table[item['PayloadIdentifier']][vers].append(itemindex)

    return {
        'hashes': hash_table,
        'receipts': pkgid_table,
        'applications': app_table,
        'installer_items': installer_item_table,
        'profiles': profile_table,
        'items': catalogitems,
    }


def find_matching_pkginfo(repo, pkginfo):
    """Looks through repo catalogs looking for matching pkginfo
    Returns a pkginfo dictionary, or an empty dict"""

    try:
        catdb = make_catalog_db(repo)
    except CatalogReadException as err:
        if pkgsinfo_items := repo.itemlist('pkgsinfo'):
            # there _are_ existing pkgsinfo items.
            # warn about the problem since we can't seem to read catalogs/all
            print(f'Could not get a list of existing items from the repo: {err}')
        return {}
    except CatalogDBException as err:
        # other error while processing catalogs/all
        print(f'Could not get a list of existing items from the repo: {err}')
        return {}

    if 'installer_item_hash' in pkginfo:
        if matchingindexes := catdb['hashes'].get(
            pkginfo['installer_item_hash']
        ):
            return catdb['items'][matchingindexes[0]]

    if 'receipts' in pkginfo:
        if pkgids := [
            item['packageid']
            for item in pkginfo['receipts']
            if 'packageid' in item
        ]:
            if possiblematches := catdb['receipts'].get(pkgids[0]):
                versionlist = list(possiblematches.keys())
                versionlist.sort(key=pkgutils.MunkiLooseVersion, reverse=True)
                # go through possible matches, newest version first
                for versionkey in versionlist:
                    testpkgindexes = possiblematches[versionkey]
                    for pkgindex in testpkgindexes:
                        testpkginfo = catdb['items'][pkgindex]
                        testpkgids = [item['packageid'] for item in
                                      testpkginfo.get('receipts', [])
                                      if 'packageid' in item]
                        if set(testpkgids) == set(pkgids):
                            return testpkginfo

    if 'installs' in pkginfo:
        if applist := [
            item
            for item in pkginfo['installs']
            if item['type'] == 'application' and 'path' in item
        ]:
            app = applist[0]['path']
            if possiblematches := catdb['applications'].get(app):
                versionlist = list(possiblematches.keys())
                versionlist.sort(key=pkgutils.MunkiLooseVersion, reverse=True)
                indexes = catdb['applications'][app][versionlist[0]]
                return catdb['items'][indexes[0]]

    if 'PayloadIdentifier' in pkginfo:
        identifier = pkginfo['PayloadIdentifier']
        if possiblematches := catdb['profiles'].get(identifier):
            versionlist = list(possiblematches.keys())
            versionlist.sort(key=pkgutils.MunkiLooseVersion, reverse=True)
            indexes = catdb['profiles'][identifier][versionlist[0]]
            return catdb['items'][indexes[0]]

    # no matches by receipts or installed applications,
    # let's try to match based on installer_item_name
    installer_item_name = os.path.basename(
        pkginfo.get('installer_item_location', ''))
    if possiblematches := catdb['installer_items'].get(installer_item_name):
        versionlist = list(possiblematches.keys())
        versionlist.sort(key=pkgutils.MunkiLooseVersion, reverse=True)
        indexes = catdb['installer_items'][installer_item_name][versionlist[0]]
        return catdb['items'][indexes[0]]

    # if we get here, we found no matches
    return {}


def get_icon_path(pkginfo):
    """Return path for icon"""
    icon_name = pkginfo.get('icon_name') or pkginfo['name']
    if not os.path.splitext(icon_name)[1]:
        icon_name += u'.png'
    return os.path.join(u'icons', icon_name)


def icon_exists_in_repo(repo, pkginfo):
    """Returns True if there is an icon for this item in the repo"""
    icon_path = get_icon_path(pkginfo)
    try:
        icon_list = list_items_of_kind(repo, 'icons')
    except munkirepo.RepoError as err:
        raise RepoCopyError(f'Unable to get list of current icons: {err}')
    return icon_path in icon_list


def add_icon_hash_to_pkginfo(pkginfo):
    """Adds the icon hash tp pkginfo if the icon exists in repo"""
    icon_path = get_icon_path(pkginfo)
    if os.path.isfile(icon_path):
        pkginfo['icon_hash'] = munkihash.getsha256hash(icon_path)


def generate_png_from_startosinstall_item(repo, dmg_path, pkginfo):
    '''Generates a product icon from a startosinstall item
    and uploads to the repo. Returns repo path to icon or None'''
    if mountpoints := dmgutils.mountdmg(dmg_path):
        mountpoint = mountpoints[0]
        app_path = osinstaller.find_install_macos_app(mountpoint)
        if icon_path := iconutils.findIconForApp(app_path):
            try:
                repo_icon_path = convert_and_install_icon(
                    repo, pkginfo, icon_path)
                dmgutils.unmountdmg(mountpoint)
                return repo_icon_path
            except RepoCopyError:
                dmgutils.unmountdmg(mountpoint)
                raise
        dmgutils.unmountdmg(mountpoint)
    return None


def generate_png_from_dmg_item(repo, dmg_path, pkginfo):
    '''Generates a product icon from a copy_from_dmg item
    and uploads to the repo. Returns repo path to icon or None'''
    if mountpoints := dmgutils.mountdmg(dmg_path):
        mountpoint = mountpoints[0]
        if apps := [
            item
            for item in pkginfo.get('items_to_copy', [])
            if item.get('source_item', '').endswith('.app')
        ]:
            app_path = os.path.join(mountpoint, apps[0]['source_item'])
            if icon_path := iconutils.findIconForApp(app_path):
                try:
                    repo_icon_path = convert_and_install_icon(
                        repo, pkginfo, icon_path)
                    dmgutils.unmountdmg(mountpoint)
                    return repo_icon_path
                except RepoCopyError:
                    dmgutils.unmountdmg(mountpoint)
                    raise
        dmgutils.unmountdmg(mountpoint)
    return None


def generate_pngs_from_pkg(repo, item_path, pkginfo, import_multiple=True):
    '''Generates a product icon (or candidate icons) from an installer pkg
    and uploads to the repo. Returns repo path to icon or None'''
    icon_paths = []
    mountpoint = None
    pkg_path = None
    if pkgutils.hasValidDiskImageExt(item_path):
        dmg_path = item_path
        if mountpoints := dmgutils.mountdmg(dmg_path):
            mountpoint = mountpoints[0]
            if pkginfo.get('package_path'):
                pkg_path = os.path.join(mountpoint, pkginfo['package_path'])
            else:
                # find first item that appears to be a pkg at the root
                for fileitem in osutils.listdir(mountpoints[0]):
                    if pkgutils.hasValidPackageExt(fileitem):
                        pkg_path = os.path.join(mountpoint, fileitem)
                        break
    elif pkgutils.hasValidPackageExt(item_path):
        pkg_path = item_path
    if pkg_path:
        if os.path.isdir(pkg_path):
            icon_paths = iconutils.extractAppIconsFromBundlePkg(pkg_path)
        else:
            icon_paths = iconutils.extractAppIconsFromFlatPkg(pkg_path)

    if mountpoint:
        dmgutils.unmountdmg(mountpoint)

    if len(icon_paths) == 1:
        return convert_and_install_icon(repo, pkginfo, icon_paths[0])
    elif len(icon_paths) > 1 and import_multiple:
        imported_paths = []
        for index, icon_path in enumerate(icon_paths, start=1):
            if imported_path := convert_and_install_icon(
                repo, pkginfo, icon_path, index=index
            ):
                imported_paths.append(imported_path)
        return "\n\t".join(imported_paths)
    return None


def convert_and_install_icon(repo, pkginfo, icon_path, index=None):
    '''Convert icon file to png and save to repo icon path.
       Returns resource path to icon in repo'''
    destination_path = 'icons'
    if index is not None:
        destination_name = pkginfo['name'] + '_' + str(index)
    else:
        destination_name = pkginfo['name']

    png_name = destination_name + u'.png'
    repo_png_path = os.path.join(destination_path, png_name)
    local_png_tmp = os.path.join(osutils.tmpdir(), png_name)
    result = iconutils.convertIconToPNG(icon_path, local_png_tmp)
    if result:
        try:
            repo.put_from_local_file(repo_png_path, local_png_tmp)
            return repo_png_path
        except munkirepo.RepoError as err:
            raise RepoCopyError(u'Error uploading icon to %s: %s'
                                % (repo_png_path, err))
    else:
        raise RepoCopyError(u'Error converting %s to png.' % icon_path)


def copy_icon_to_repo(repo, iconpath):
    """Saves a product icon to the repo. Returns repo path."""
    destination_path = 'icons'
    icon_name = os.path.basename(iconpath)
    destination_path_name = os.path.join(destination_path, icon_name)

    try:
        icon_list = list_items_of_kind(repo, 'icons')
    except munkirepo.RepoError as err:
        raise RepoCopyError(u'Unable to get list of current icons: %s' % err)
    if destination_path_name in icon_list:
        # remove any existing icon in the repo
        try:
            repo.delete(destination_path_name)
        except munkirepo.RepoError as err:
            raise RepoCopyError(u'Could not remove existing %s: %s'
                                % (destination_path_name, err))
    print(u'Copying %s to %s...' % (icon_name, destination_path_name))
    try:
        repo.put_from_local_file(destination_path_name, iconpath)
        return destination_path_name
    except munkirepo.RepoError as err:
        raise RepoCopyError(u'Unable to copy %s to %s: %s'
                            % (iconpath, destination_path_name, err))


def extract_and_copy_icon(repo, installer_item, pkginfo, import_multiple=True):
    '''Extracts an icon from an installer item, converts it to a png, and
    copies to repo. Returns repo path to imported icon'''
    installer_type = pkginfo.get('installer_type')
    if installer_type == 'copy_from_dmg':
        return generate_png_from_dmg_item(repo, installer_item, pkginfo)
    elif installer_type == 'startosinstall':
        return generate_png_from_startosinstall_item(
            repo, installer_item, pkginfo)
    elif installer_type in [None, '']:
        return generate_pngs_from_pkg(
            repo, installer_item, pkginfo, import_multiple=import_multiple)
    raise RepoCopyError(
        'Can\'t generate icons from installer_type: %s.' % installer_type)
