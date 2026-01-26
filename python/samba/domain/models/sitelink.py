# Unix SMB/CIFS implementation.
#
# Connection model for ntDSConnection objects.
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

from .fields import BooleanField, DnField, IntegerField, StringField, BinaryField
from .model import Model

# SiteLink cost values range
NTDSSITELINK_MIN_COST = 1
NTDSSITELINK_MAX_COST = 99999

# SiteLink interval values range
NTDSSITELINK_MIN_INTERVAL = 15
NTDSSITELINK_MAX_INTERVAL = 10080

# SiteLink options bit flags controlling replication behavior
NTDSSITELINK_OPT_USE_NOTIFY = 0x00000001    # Enables replication notifications between DCs in different sites
NTDSSITELINK_OPT_TWOWAY_SYNC = 0x00000002   # Forces a replication cycle in the opposite direction at the end of a replication cycle
NTDSSITELINK_OPT_DISABLE_COMPRESSION = 0x00000004  # Disables compression of replication response messages between DCs
NTDSSITELINK_OPT_COMBINED = NTDSSITELINK_OPT_USE_NOTIFY | NTDSSITELINK_OPT_TWOWAY_SYNC | NTDSSITELINK_OPT_DISABLE_COMPRESSION

class SiteLink(Model):
    """SiteLink model representing the connection between two or more sites.

    A site link connects two or more sites and contains information about
    how replication occurs between those sites, including cost, schedule,
    and various replication behavior options.
    """
    name = StringField("cn")
    siteList = DnField("siteList", many=True)
    cost = IntegerField("cost")
    replInterval = IntegerField("replInterval")
    schedule = BinaryField("schedule")
    options = IntegerField("options")

    show_in_advanced_view_only = BooleanField("showInAdvancedViewOnly")
    system_flags = IntegerField("systemFlags", readonly=True)

    @staticmethod
    def get_base_dn(samdb, transport="ip"):
        """Return the base DN for SiteLink objects.

        The SiteLink objects are stored under:
        CN=IP,CN=Inter-Site Transports,CN=Sites if transport is IP
        CN=SMTP,CN=Inter-Site Transports,CN=Sites if transport is SMTP

        :param samdb: SamDB connection
        :param transport: Transport type ("ip" or "smtp")
        :return: Dn to use for new objects
        """
        base_dn = samdb.get_config_basedn()
        transport_name = "IP" if transport.lower() == "ip" else "SMTP"
        base_dn.add_child(f"CN={transport_name},CN=Inter-Site Transports,CN=Sites")
        return base_dn

    @staticmethod
    def get_object_class():
        """Return the objectClass for SiteLink objects."""
        return "siteLink"