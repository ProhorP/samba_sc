# Unix SMB/CIFS implementation.
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

import samba.getopt as options
from samba.domain.models import Server, Site
from samba.domain.models.exceptions import ModelError
from samba.netcmd import Command, CommandError, Option


class cmd_servers_list(Command):
    """List domain controllers in a site."""

    synopsis = "%prog <site> [options]"

    takes_args = ["sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, sitename, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, output_format=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            site = Site.get(ldb, cn=sitename)
        except ModelError as e:
            raise CommandError(e)

        if site is None:
            raise CommandError(f"Site {sitename} not found.")

        servers_dn = Server.get_base_dn(ldb, site_cn=sitename)

        try:
            servers_dict = {server.cn: server.as_dict()
                          for server in Server.query(ldb, base_dn=str(servers_dn))}
        except ModelError as e:
            raise CommandError(e)

        if output_format == "json":
            self.print_json(servers_dict)
        else:
            for server in servers_dict.keys():
                self.outf.write(f"{server}\n")

class cmd_servers_view(Command):
    """View details of a domain controller in a site."""

    synopsis = "%prog <server> <site> [options]"

    takes_args = ["sitename", "servername"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, sitename, servername, hostopts=None, sambaopts=None,
            credopts=None, versionopts=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            site = Site.get(ldb, cn=sitename)
        except ModelError as e:
            raise CommandError(e)

        if site is None:
            raise CommandError(f"Site {sitename} not found.")

        servers_dn = Server.get_base_dn(ldb, site_cn=sitename)

        try:
            server = Server.get(ldb, cn=servername, base_dn=str(servers_dn))
        except ModelError as e:
            raise CommandError(e)

        if server is None:
            raise CommandError(f"Server {servername} not found in site {sitename}.")

        self.print_json(server.as_dict())
