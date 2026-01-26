# python site-link manipulation code
#
# Copyright (C) BaseALT Ltd. 2026
#
# Written by Vladimir Rubanov <august@altlinux.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""Manipulating site-links."""

import ldb
from ldb import FLAG_MOD_ADD, LdbError


class SiteLinkException(Exception):
    """Base element for Site-Links errors"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%s: %s" % (self.__class__.__name__, self.value)


class SiteLinkNotFoundException(SiteLinkException):
    """Raised when the site-link is not found and it's expected to exists."""


class SiteLinkAlreadyExistsException(SiteLinkException):
    """Raised when the site-link already exists and it's expected not to exists."""


class SiteNotFoundException(SiteLinkException):
    """Raised when a site is not found and it's expected to exists."""


def create_site_link(samdb, configDn, baseDn, siteLinkName, sites, cost=None, replInterval=None, schedule=None, options=None):
    """
    Create a new site-link between two or more sites.

    :param samdb: A samdb connection
    :param configDn: The DN of the configuration partition
    :param baseDn: The DN of the site-links
    :param siteLinkName: Name of the site-link to create (required)
    :param sites: List of site names (minimum 2) connected by this link
    :param cost: Administrator-defined cost value (optional)
    :param replInterval: Replication interval in minutes (optional)
    :param schedule: Replication schedule as a string (optional)
    :param options: SiteLink options bit flags controlling replication behavior (optional)
    :return: True upon success
    :raise SiteLinkAlreadyExists: if site-link already exists.
    :raise SiteNotFound: if any site doesn't exist.
    """
    
    ret = samdb.search(base=configDn, scope=ldb.SCOPE_SUBTREE,
                       expression='(&(objectclass=siteLink)(cn=%s))' % siteLinkName)
    if len(ret) != 0:
        raise SiteLinkAlreadyExistsException('A site-link with the name %s already exists' % siteLinkName)

    for site in sites:
        ret = samdb.search(base=configDn, scope=ldb.SCOPE_SUBTREE,
                           expression='(&(objectclass=Site)(cn=%s))' % site)
        if len(ret) == 0:
            raise SiteNotFoundException('Site %s does not exist' % site)

    if len(sites) < 2:
        raise SiteLinkException('At least 2 sites are required to create a site-link')

    m = ldb.Message()
    m.dn = ldb.Dn(samdb, "CN=%s,%s" % (siteLinkName, str(baseDn)))
    m["objectclass"] = ldb.MessageElement("siteLink", FLAG_MOD_ADD, "objectclass")
    
    sites_dn_list = ["CN=%s,CN=Sites,%s" % (site, str(configDn)) for site in sites]
    m["siteList"] = ldb.MessageElement(sites_dn_list, FLAG_MOD_ADD, "siteList")
    
    if cost is not None:
        m["cost"] = ldb.MessageElement(str(cost), FLAG_MOD_ADD, "cost")
    
    if replInterval is not None:
        m["replInterval"] = ldb.MessageElement(str(replInterval), FLAG_MOD_ADD, "replInterval")
    
    if schedule is not None:
        m["schedule"] = ldb.MessageElement(schedule, FLAG_MOD_ADD, "schedule")
    
    if options is not None:
        m["options"] = ldb.MessageElement(str(options), FLAG_MOD_ADD, "options")

    samdb.add(m)

    return True

def delete_site_link(samdb, baseDn, siteLinkName):
    """
    Delete an existing site-link.

    :param samdb: A samdb connection
    :param baseDn: The DN of the site-links
    :param siteLinkName: Name of the site-link to delete (required)
    :return: True upon success
    :raise SiteLinkNotFound: if site-link doesn't exist.
    """

    dnsitelink = ldb.Dn(samdb, str(baseDn))
    try:
        dnsitelink.add_child("CN=X")
    except ldb.LdbError:
        raise SiteLinkException("dnsitelink.add_child() failed")
    dnsitelink.set_component(0, "CN", siteLinkName)

    try:
        ret = samdb.search(base=dnsitelink, scope=ldb.SCOPE_BASE,
                           expression="objectClass=siteLink")
        if len(ret) != 1:
            raise SiteLinkNotFoundException('Site-link %s does not exist' % siteLinkName)
    except LdbError as e:
        (enum, estr) = e.args
        if enum == ldb.ERR_NO_SUCH_OBJECT:
            raise SiteLinkNotFoundException('Site-link %s does not exist' % siteLinkName)

    samdb.delete(dnsitelink, ["tree_delete:0"])

    return True


def rename_site_link(samdb, baseDn, old_name, new_name):
    """
    Rename an existing site-link.

    :param samdb: A samdb connection
    :param baseDn: The DN of the site-links
    :param old_name: Current name of the site-link to rename (required)
    :param new_name: New name for the site-link (required)
    :return: True upon success
    :raise SiteLinkNotFound: if site-link doesn't exist.
    :raise SiteLinkAlreadyExists: if new name already exists.
    """
    
    ret = samdb.search(base=baseDn, scope=ldb.SCOPE_SUBTREE,
                       expression='(&(objectclass=siteLink)(cn=%s))' % new_name)
    if len(ret) != 0:
        raise SiteLinkAlreadyExistsException('A site-link with the name %s already exists' % new_name)

    oldDn = ldb.Dn(samdb, str(baseDn))
    try:
        oldDn.add_child("CN=X")
    except ldb.LdbError:
        raise SiteLinkException("oldDn.add_child() failed")
    oldDn.set_component(0, "CN", old_name)

    newDn = ldb.Dn(samdb, str(baseDn))
    try:
        newDn.add_child("CN=X")
    except ldb.LdbError:
        raise SiteLinkException("newDn.add_child() failed")
    newDn.set_component(0, "CN", new_name)

    try:
        ret = samdb.search(base=oldDn, scope=ldb.SCOPE_BASE,
                           expression="objectClass=siteLink")
        if len(ret) != 1:
            raise SiteLinkNotFoundException('Site-link %s does not exist' % old_name)
    except LdbError as e:
        (enum, estr) = e.args
        if enum == ldb.ERR_NO_SUCH_OBJECT:
            raise SiteLinkNotFoundException('Site-link %s does not exist' % old_name)
    
    samdb.rename(oldDn, newDn)

    return True
