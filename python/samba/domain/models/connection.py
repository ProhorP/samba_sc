# Unix SMB/CIFS implementation.
#
# Connection model for ntDSConnection objects.
#
# Copyright (C) BaseALT Ltd. 2025
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

from .fields import BooleanField, BinaryField, DnField, IntegerField, StringField
from .model import Model

import re

NTDSCONN_OPT_IS_GENERATED = 0x00000001
NTDSCONN_OPT_TWOWAY_SYNC = 0x00000002
NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT = 0x00000004
NTDSCONN_OPT_USE_NOTIFY = 0x00000008
NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION = 0x00000010
NTDSCONN_OPT_USER_OWNED_SCHEDULE = 0x00000020

SERVER_NAME_PATTERN = re.compile(r'CN=NTDS Settings\s*,\s*CN=([^,\s]+)')

class Connection(Model):
    from_server = DnField("fromServer")
    options = IntegerField("options", readonly=True)
    schedule = BinaryField("schedule")
    show_in_advanced_view_only = BooleanField("showInAdvancedViewOnly")
    system_flags = IntegerField("systemFlags", readonly=True)

    @staticmethod
    def get_base_dn(samdb):
        """Return the base DN for the Connection model.

        :param samdb: SamDB connection
        :return: Dn to use for new objects
        """
        base_dn = samdb.get_config_basedn()
        base_dn.add_child("CN=Sites")
        return base_dn

    @staticmethod
    def get_object_class():
        return "nTDSConnection"

    def get_from_server_cn(self):
        """Extracts the server name from an fromServer DN string.
            
        Returns:
            str: Server name (e.g. "DC") or None if not found.
        """
        match = SERVER_NAME_PATTERN.search(str(self.from_server))
        return match.group(1) if match else None