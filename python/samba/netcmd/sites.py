# sites management
#
# Copyright Matthieu Patou <mat@matws.net> 2011
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
from samba import schedule, sites, subnets
from samba.domain.models import Site, Subnet, Connection
from samba.domain.models.exceptions import ModelError
from samba.netcmd import Command, CommandError, Option, SuperCommand

from .servers import cmd_servers_list, cmd_servers_view, cmd_servers_move
from .sitelinks import (
    cmd_sitelinks_list,
    cmd_sitelinks_view, 
    cmd_site_links_create,
    cmd_site_links_modify,
    cmd_site_links_delete,
    cmd_site_links_rename,
    cmd_site_links_add_site,
    cmd_site_links_delete_site,
    cmd_site_links_schedule
)

class cmd_sites_list(Command):
    """List sites."""

    synopsis = "%prog [options]"

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

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, output_format=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        # sites by cn.
        try:
            sites_dict = {site.cn: site.as_dict()
                          for site in Site.query(ldb)}
        except ModelError as e:
            raise CommandError(e)

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json(sites_dict)
        else:
            for site in sites_dict.keys():
                self.outf.write(f"{site}\n")


class cmd_sites_view(Command):
    """View one site."""

    synopsis = "%prog <site> [options]"

    takes_args = ["sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, sitename, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            site = Site.get(ldb, cn=sitename)
        except ModelError as e:
            raise CommandError(e)

        # Check if site exists first.
        if site is None:
            raise CommandError(f"Site {sitename} not found.")

        # Display site as JSON.
        self.print_json(site.as_dict())


class cmd_sites_create(Command):
    """Create a new site."""

    synopsis = "%prog <site> [options]"

    takes_args = ["sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, sitename, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        samdb.transaction_start()
        try:
            sites.create_site(samdb, samdb.get_config_basedn(), sitename)
            samdb.transaction_commit()
        except sites.SiteAlreadyExistsException as e:
            samdb.transaction_cancel()
            raise CommandError("Error while creating site %s, error: %s" %
                               (sitename, str(e)))

        self.outf.write("Site %s created !\n" % sitename)


class cmd_sites_delete(Command):
    """Delete an existing site."""

    synopsis = "%prog <site> [options]"

    takes_args = ["sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, sitename, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        samdb.transaction_start()
        try:
            sites.delete_site(samdb, samdb.get_config_basedn(), sitename)
            samdb.transaction_commit()
        except sites.SiteException as e:
            samdb.transaction_cancel()
            raise CommandError(
                "Error while removing site %s, error: %s" % (sitename, str(e)))

        self.outf.write("Site %s removed!\n" % sitename)


class cmd_sites_subnet_list(Command):
    """List subnets."""

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

        # Check if site exists first.
        if site is None:
            raise CommandError(f"Site {sitename} not found.")

        # subnets by cn.
        try:
            subnets_dict = {subnet.cn: subnet.as_dict()
                            for subnet in Subnet.query(ldb,
                                                       site_object=str(site.dn))}
        except ModelError as e:
            raise CommandError(e)

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json(subnets_dict)
        else:
            for subnet in subnets_dict.keys():
                self.outf.write(f"{subnet}\n")


class cmd_sites_subnet_view(Command):
    """View subnet details."""

    synopsis = "%prog <subnet> [options]"

    takes_args = ["subnetname"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, subnetname, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            subnet = Subnet.get(ldb, cn=subnetname)
        except ModelError as e:
            raise CommandError(e)

        # Check if subnet exists first.
        if subnet is None:
            raise CommandError(f"Subnet {subnetname} not found.")

        # Display subnet as JSON.
        self.print_json(subnet.as_dict())


class cmd_sites_subnet_create(Command):
    """Create a new subnet."""
    synopsis = "%prog <subnet> <site-of-subnet> [options]"
    takes_args = ["subnetname", "site_of_subnet"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, subnetname, site_of_subnet, hostopts=None, sambaopts=None,
            credopts=None, versionopts=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        samdb.transaction_start()
        try:
            subnets.create_subnet(samdb, samdb.get_config_basedn(), subnetname,
                                  site_of_subnet)
            samdb.transaction_commit()
        except subnets.SubnetException as e:
            samdb.transaction_cancel()
            raise CommandError("Error while creating subnet %s: %s" %
                               (subnetname, e))

        self.outf.write("Subnet %s created !\n" % subnetname)


class cmd_sites_subnet_delete(Command):
    """Delete an existing subnet."""

    synopsis = "%prog <subnet> [options]"

    takes_args = ["subnetname"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, subnetname, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        samdb.transaction_start()
        try:
            subnets.delete_subnet(samdb, samdb.get_config_basedn(), subnetname)
            samdb.transaction_commit()
        except subnets.SubnetException as e:
            samdb.transaction_cancel()
            raise CommandError("Error while removing subnet %s, error: %s" %
                               (subnetname, e))

        self.outf.write("Subnet %s removed!\n" % subnetname)


class cmd_sites_subnet_set_site(Command):
    """Assign a subnet to a site."""
    synopsis = "%prog <subnet> <site-of-subnet> [options]"
    takes_args = ["subnetname", "site_of_subnet"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, subnetname, site_of_subnet, hostopts=None, sambaopts=None,
            credopts=None, versionopts=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        samdb.transaction_start()
        try:
            subnets.set_subnet_site(samdb, samdb.get_config_basedn(),
                                    subnetname, site_of_subnet)
            samdb.transaction_commit()
        except subnets.SubnetException as e:
            samdb.transaction_cancel()
            raise CommandError("Error assigning subnet %s to site %s: %s" %
                               (subnetname, site_of_subnet, e))

        print(("Subnet %s shifted to site %s" %
               (subnetname, site_of_subnet)), file=self.outf)


class cmd_sites_subnet(SuperCommand):
    """Subnet management subcommands."""
    subcommands = {
        "create": cmd_sites_subnet_create(),
        "remove": cmd_sites_subnet_delete(),
        "list": cmd_sites_subnet_list(),
        "view": cmd_sites_subnet_view(),
        "set-site": cmd_sites_subnet_set_site(),
    }


class cmd_sites_connection_list(Command):
    """List connections."""

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

        # Check if site exists first.
        if site is None:
            raise CommandError(f"Site {sitename} not found.")

        try:
            site_dn = site.dn
            connections_dict = {}

            for connection in Connection.query(ldb, base_dn=site_dn):
                connection_name = connection.cn
                server_cn = connection.get_from_server_cn()
                site_cn = site.cn

                connections_dict[connection_name] = {
                    'Connection': connection_name,
                    'Server': server_cn,
                    'Site': site_cn
                }
        except ModelError as e:
            raise CommandError(e)

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json(connections_dict)
        else:
            for connection_name, info in connections_dict.items():
                self.outf.write(f"Connection: {info['Connection']}, Server: {info['Server']}, Site: {info['Site']}\n")


class cmd_sites_connection_schedule_show(Command):
    """Show current connection schedule."""

    synopsis = "%prog <connection> [options]"

    takes_args = ["connectionname"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--show-legend", help="Show legend for schedule display",
               dest="show_legend", action="store_true", default=False),
    ]

    def run(self, connectionname, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, show_legend=False):
        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            connection = Connection.get(ldb, cn=connectionname)
        except ModelError as e:
            raise CommandError(e)

        # Check if connection exists first.
        if connection is None:
            raise CommandError(f"Connection {connectionname} not found.")

        self.outf.write(f"ConnectionName: {connection.cn}\n")
        self.outf.write(f"SourceComputerName: {connection.get_from_server_cn()}\n")
        self.outf.write(f"BandwidthDetail: \n\n")

        schedule.show_schedule(connection.schedule, self.outf.write, show_legend)


class cmd_sites_connection_schedule_set(Command):
    """Set current connection schedule."""

    synopsis = "%prog <connection_name> [options]"

    takes_args = ["connection_name"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--days", help="List of days (1=Monday through 7=Sunday), comma-separated",
               dest="days", type=str, default=None),
        Option("--hours", help="List of hours (1-24), comma-separated",
               dest="hours", type=str, default=None),
        Option("--slot", help="Amount of replication per hour: 0=None, 1=Once per Hour, 2=Twice per Hour, 3=Four Times per Hour",
               dest="slot", type=int, default=None),
    ]

    def run(self, connection_name, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, days=None, hours=None, slot=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        if days is None or hours is None or slot is None:
            raise CommandError("--days, --hours, and --slot must be specified")

        parsed_days = []
        if days is not None:
            try:
                parsed_days = [int(d.strip()) for d in days.split(',')]
                for day in parsed_days:
                    if day < 1 or day > 7:
                        raise ValueError(f"Day {day} must be between 1 (Monday) and 7 (Sunday)")
            except ValueError as e:
                raise CommandError(f"Invalid days format: {e}")

        parsed_hours = []
        if hours is not None:
            try:
                parsed_hours = [int(h.strip()) for h in hours.split(',')]
                for hour in parsed_hours:
                    if hour < 1 or hour > 24:
                        raise ValueError(f"Hour {hour} must be between 1 and 24")
            except ValueError as e:
                raise CommandError(f"Invalid hours format: {e}")

        if slot is None or slot < 0 or slot > 3:
            raise CommandError(f"Slot {slot} must be between 0 and 3")

        try:
            connection = Connection.get(samdb, cn=connection_name)
        except ModelError as e:
            raise CommandError(e)

        # Check if connection exists first.
        if connection is None:
            raise CommandError(f"Connection {connection_name} not found.")

        samdb.transaction_start()
        try:
            new_schedule = schedule.set_schedule_slots(connection.schedule,
                                                        parsed_days,
                                                        parsed_hours,
                                                        slot)
            schedule.set_connection_schedule(samdb, connection, new_schedule)
            samdb.transaction_commit()
        except schedule.ScheduleException as e:
            samdb.transaction_cancel()
            raise CommandError("Error assigning new schedule to connection %s: %s" %
                               (connection_name, e))

        print(("New schedule has been assigned to connection %s" %
               (connection_name)), file=self.outf)

class cmd_sites_connection_schedule_apply_preset(Command):
    """Apply predefined preset to current connection schedule.
    
    Available presets:
    business_hours - Monday-Friday, 9 AM to 5 PM (4 times per hour)
    weekends       - Saturday and Sunday, all day (4 times per hour)
    off_hours      - Monday-Friday, 6 PM to 8 AM (2 times per hour)
    all            - All days, all hours (4 times per hour)
    none           - No replication at all
    """

    synopsis = "%prog <connection_name> <preset> [options]"

    takes_args = ["connection_name", "preset" ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, connection_name, preset, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            connection = Connection.get(samdb, cn=connection_name)
        except ModelError as e:
            raise CommandError(e)

        # Check if connection exists first.
        if connection is None:
            raise CommandError(f"Connection {connection_name} not found.")

        samdb.transaction_start()
        try:
            new_schedule = schedule.apply_schedule_preset(connection.schedule, preset)
            schedule.set_connection_schedule(samdb, connection, new_schedule)
            samdb.transaction_commit()
        except schedule.ScheduleException as e:
            samdb.transaction_cancel()
            raise CommandError("Error assigning new schedule to connection %s: %s" %
                               (connection_name, e))

        print(("New schedule has been assigned to connection %s" %
               (connection_name)), file=self.outf)

class cmd_sites_connection_schedule(SuperCommand):
    """Connection schedule management subcommands."""
    subcommands = {
        "show": cmd_sites_connection_schedule_show(),
        "set": cmd_sites_connection_schedule_set(),
        "preset": cmd_sites_connection_schedule_apply_preset(),
    }


class cmd_sites_connection(SuperCommand):
    """Connection management subcommands."""
    subcommands = {
        "list": cmd_sites_connection_list(),
        "schedule": cmd_sites_connection_schedule(),
    }

class cmd_sites_sitelinks(SuperCommand):
    """Sitelink management subcommands."""
    subcommands = {
        "list": cmd_sitelinks_list(),
        "view": cmd_sitelinks_view(),
        "create": cmd_site_links_create(),
        "modify": cmd_site_links_modify(),
        "delete": cmd_site_links_delete(),
        "rename": cmd_site_links_rename(),
        "add-site": cmd_site_links_add_site(),
        "delete-site": cmd_site_links_delete_site(),
        "schedule": cmd_site_links_schedule(),
    }

class cmd_sites_servers(SuperCommand):
    """Server management subcommands."""
    subcommands = {
        "list": cmd_servers_list(),
        "view": cmd_servers_view(),
        "move": cmd_servers_move(),
    }

class cmd_sites(SuperCommand):
    """Sites management."""
    subcommands = {}
    subcommands["list"] = cmd_sites_list()
    subcommands["view"] = cmd_sites_view()
    subcommands["create"] = cmd_sites_create()
    subcommands["remove"] = cmd_sites_delete()
    subcommands["subnet"] = cmd_sites_subnet()
    subcommands["connection"] = cmd_sites_connection()
    subcommands["sitelinks"] = cmd_sites_sitelinks()
    subcommands["servers"] = cmd_sites_servers()
