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


class cmd_servers_move(Command):
    """Move a domain controller from one site to another."""

    synopsis = "%prog <servername> --from <source_site> --to <destination_site> [options]"

    takes_args = ["servername"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--from", dest="source_site", required=True,
               help="Name of the source site"),
        Option("--to", dest="destination_site", required=True,
               help="Name of the destination site"),
    ]

    def run(self, servername, source_site, destination_site, hostopts=None,
            sambaopts=None, credopts=None, versionopts=None):

        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            source_site_obj = Site.get(samdb, cn=source_site)
        except ModelError as e:
            raise CommandError(e)

        if source_site_obj is None:
            raise CommandError(f"Source site '{source_site}' not found.")

        servers_dn = Server.get_base_dn(samdb, site_cn=source_site)
        try:
            server = Server.get(samdb, cn=servername, base_dn=str(servers_dn))
        except ModelError as e:
            raise CommandError(e)

        if server is None:
            raise CommandError(f"Server '{servername}' not found in source site '{source_site}'.")

        try:
            dest_site_obj = Site.get(samdb, cn=destination_site)
        except ModelError as e:
            raise CommandError(e)

        if dest_site_obj is None:
            raise CommandError(f"Destination site '{destination_site}' not found.")

        dest_servers_dn = Server.get_base_dn(samdb, site_cn=destination_site)
        try:
            existing_server = Server.get(samdb, cn=servername, base_dn=str(dest_servers_dn))
        except ModelError as e:
            raise CommandError(e)

        if existing_server is not None:
            raise CommandError(f"Server '{servername}' already exists in destination site '{destination_site}'.")

        samdb.transaction_start()
        try:
            old_dn = server.dn
            new_dn = Server.get_base_dn(samdb, site_cn=destination_site)
            new_dn.add_child(f"CN={servername}")
            samdb.rename(old_dn, new_dn)

            samdb.transaction_commit()
        except Exception as e:
            samdb.transaction_cancel()
            raise CommandError(f"Error moving server '{servername}' from site '{source_site}' to site '{destination_site}': {e}")

        self.outf.write(f"Server '{servername}' moved from site '{source_site}' to site '{destination_site}' successfully.\n")
