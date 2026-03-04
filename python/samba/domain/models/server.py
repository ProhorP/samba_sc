# Unix SMB/CIFS implementation.
#
# Server model for Server Object objects.
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

from .fields import BooleanField, DnField, IntegerField, StringField
from .model import Model


class Server(Model):
    """Server model representing a domain controller in a site.

    A server object represents a DC in Active Directory and contains
    information about the DC including its DNS hostname, reference to
    the domain controller object, and various configuration flags.
    """
    dNSHostName = StringField("dNSHostName")
    mailAddress = StringField("mailAddress")
    serverReference = DnField("serverReference")
    show_in_advanced_view_only = BooleanField("showInAdvancedViewOnly")
    system_flags = IntegerField("systemFlags", readonly=True)

    @staticmethod
    def get_base_dn(samdb, site_cn=None):
        """Return the base DN for the Server model.

        :param samdb: SamDB connection
        :param site_cn: Optional site name to get servers container for specific site
        :return: Dn to use for new objects
        """
        base_dn = samdb.get_config_basedn()
        base_dn.add_child("CN=Sites")
        if site_cn:
            base_dn.add_child(f"CN={site_cn}")
        base_dn.add_child("CN=Servers")
        return base_dn

    @staticmethod
    def get_object_class():
        return "server"
