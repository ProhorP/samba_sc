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

import samba.getopt as options
from samba import sitelinks, schedule
from samba.domain.models import Site, SiteLink
from samba.domain.models.sitelink import NTDSSITELINK_MIN_COST, NTDSSITELINK_MAX_COST
from samba.domain.models.sitelink import NTDSSITELINK_MIN_INTERVAL, NTDSSITELINK_MAX_INTERVAL
from samba.domain.models.sitelink import NTDSSITELINK_OPT_COMBINED
from samba.domain.models.exceptions import ModelError
from samba.netcmd import Command, CommandError, Option, SuperCommand
from samba.netcmd.validators import Range
from samba.kcc.kcc_utils import new_connection_schedule
from samba.ndr import ndr_pack

import ldb
from ldb import FLAG_MOD_REPLACE, LdbError


class cmd_sitelinks_list(Command):
    """List sitelinks."""

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
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, output_format=None, transport=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        # Get the appropriate base DN based on transport
        base_dn = SiteLink.get_base_dn(ldb, transport=transport)

        # sitelinks by cn.
        try:
            sitelinks_dict = {sitelink.cn: sitelink.as_dict()
                            for sitelink in SiteLink.query(ldb, base_dn=base_dn)}
        except ModelError as e:
            raise CommandError(e)
        except Exception as e:
            raise CommandError(e)

        # Using json output format gives more detail.
        if output_format == "json":
            # Filter out binary fields that can't be JSON serialized
            for sitelink_name, sitelink_data in sitelinks_dict.items():
                if 'schedule' in sitelink_data:
                    del sitelink_data['schedule']

            self.print_json(sitelinks_dict)
        else:
            for sitelink in sitelinks_dict.keys():
                self.outf.write(f"{sitelink}\n")

class cmd_sitelinks_view(Command):
    """View one sitelink."""

    synopsis = "%prog <sitelink> [options]"

    takes_args = ["sitelinkname"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
    ]

    def run(self, sitelinkname, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, transport=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        # Get the appropriate base DN based on transport
        base_dn = SiteLink.get_base_dn(ldb, transport=transport)

        try:
            sitelink = SiteLink.get(ldb, cn=sitelinkname, base_dn=base_dn)
        except ModelError as e:
            raise CommandError(e)

        # Check if sitelink exists first.
        if sitelink is None:
            raise CommandError(f"Sitelink {sitelink} not found.")

        sitelink_data = sitelink.as_dict()
        if 'schedule' in sitelink_data:
            del sitelink_data['schedule']

        self.print_json(sitelink_data)


class cmd_site_links_create(Command):
    """Create a new site-link."""

    synopsis = "%prog <name> --sites <sites...> [options]"

    takes_args = ["sitelink_name"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
        Option("--sites", help="Comma-separated list of sites",
               dest="sites", required=True),
        Option("--cost", help="Replication cost (integer value)",
               dest="cost", type=int, default=100,
               validators=[Range(NTDSSITELINK_MIN_COST, NTDSSITELINK_MAX_COST)]),
        Option("--repl-interval", help="Replication interval in minutes",
               dest="repl_interval", type=int, default=180,
               validators=[Range(NTDSSITELINK_MIN_INTERVAL, NTDSSITELINK_MAX_INTERVAL)]),
        Option("--schedule", help="Replication schedule - the name of one of the presets for schedule",
               dest="schedule", type=str, default=None),
        Option("--options", help="SiteLink options bit flags (0=No options, 1=USE_NOTIFY, 2=TWO_WAY_SYNC, 4=DISABLE_COMPRESSION)",
               dest="options", type=int, default=0,
               validators=[Range(0, NTDSSITELINK_OPT_COMBINED)]),
    ]

    def run(self, sitelink_name, sites, hostopts=None, sambaopts=None,
            credopts=None, versionopts=None, transport=None, cost=None,
            repl_interval=None, schedule=None, options=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            sites_dns = [site.strip() for site in sites.split(',')]
            if len(sites_dns) < 2:
                raise CommandError("At least two sites must be specified in the site-list")
        except Exception as e:
            raise CommandError(f"Invalid site-list format: {e}")

        base_dn = SiteLink.get_base_dn(samdb, transport=transport)

        samdb.transaction_start()
        try:
            sitelinks.create_site_link(samdb, samdb.get_config_basedn(), base_dn,
                                       sitelink_name, sites_dns, cost, repl_interval,
                                       schedule, options)
            samdb.transaction_commit()
        except (sitelinks.SiteLinkAlreadyExistsException,
                sitelinks.SiteNotFoundException,
                sitelinks.SiteLinkException) as e:
            samdb.transaction_cancel()
            raise CommandError("Error while creating site-link %s, error: %s" %
                               (sitelink_name, str(e)))

        self.outf.write("Site-link %s created !\n" % sitelink_name)


class cmd_site_links_delete(Command):
    """Delete an existing site-link."""

    synopsis = "%prog <name> [options]"

    takes_args = ["sitelink_name"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
    ]

    def run(self, sitelink_name, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, transport=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        base_dn = SiteLink.get_base_dn(samdb, transport=transport)

        samdb.transaction_start()
        try:
            sitelinks.delete_site_link(samdb, base_dn, sitelink_name)
            samdb.transaction_commit()
        except (sitelinks.SiteLinkNotFoundException,
                sitelinks.SiteLinkException) as e:
            samdb.transaction_cancel()
            raise CommandError("Error while removing site-link %s, error: %s" %
                               (sitelink_name, str(e)))

        self.outf.write("Site-link %s removed!\n" % sitelink_name)


class cmd_site_links_rename(Command):
    """Rename an existing site-link."""

    synopsis = "%prog <old-name> <new-name> [options]"

    takes_args = ["old_name", "new_name"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
    ]

    def run(self, old_name, new_name, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, transport=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        base_dn = SiteLink.get_base_dn(samdb, transport=transport)

        samdb.transaction_start()
        try:
            sitelinks.rename_site_link(samdb, base_dn, old_name, new_name)
            samdb.transaction_commit()
        except (sitelinks.SiteLinkNotFoundException,
                sitelinks.SiteLinkAlreadyExistsException,
                sitelinks.SiteLinkException) as e:
            samdb.transaction_cancel()
            raise CommandError("Error while renaming site-link from %s to %s, error: %s" %
                               (old_name, new_name, str(e)))

        self.outf.write("Site-link renamed from %s to %s!\n" % (old_name, new_name))


class cmd_site_links_add_site(Command):
    """Add a site to an existing site-link."""

    synopsis = "%prog <sitelink> <site> [options]"

    takes_args = ["sitelinkname", "sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
    ]

    def run(self, sitelinkname, sitename, hostopts=None, sambaopts=None,
            credopts=None, versionopts=None, transport=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        base_dn = SiteLink.get_base_dn(samdb, transport=transport)

        try:
            sitelink = SiteLink.get(samdb, cn=sitelinkname, base_dn=base_dn)
        except ModelError as e:
            raise CommandError(e)

        if sitelink is None:
            raise CommandError(f"Sitelink {sitelinkname} not found.")

        try:
            site = Site.get(samdb, cn=sitename)
        except ModelError as e:
            raise CommandError(e)

        if site is None:
            raise CommandError(f"Site {sitename} not found.")

        existing_sites = sitelink.siteList or []
        for existing_site_dn in existing_sites:
            try:
                existing_site = Site.get(samdb, dn=existing_site_dn)
                if existing_site and existing_site.cn == sitename:
                    raise CommandError(f"Site {sitename} is already present in site-link {sitelinkname}")
            except ModelError:
                raise CommandError(f"Unable to get existing site {existing_site}.")

        samdb.transaction_start()
        try:
            if sitelink.siteList is None:
                sitelink.siteList = []
            
            new_site_list = list(sitelink.siteList)
            new_site_list.append(site.dn)
            
            m = ldb.Message()
            m.dn = sitelink.dn

            m["siteList"] = ldb.MessageElement(new_site_list, FLAG_MOD_REPLACE, "siteList")

            samdb.modify(m)

            samdb.transaction_commit()
        except Exception as e:
            samdb.transaction_cancel()
            raise CommandError(f"Error while adding site {sitename} to site-link {sitelinkname}: {e}")

        self.outf.write("Site %s added to site-link %s!\n" % (sitename, sitelinkname))


class cmd_site_links_delete_site(Command):
    """Delete a site from an existing site-link."""

    synopsis = "%prog <sitelink> <site> [options]"

    takes_args = ["sitelinkname", "sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
    ]

    def run(self, sitelinkname, sitename, hostopts=None, sambaopts=None,
            credopts=None, versionopts=None, transport=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        base_dn = SiteLink.get_base_dn(samdb, transport=transport)

        try:
            sitelink = SiteLink.get(samdb, cn=sitelinkname, base_dn=base_dn)
        except ModelError as e:
            raise CommandError(e)

        if sitelink is None:
            raise CommandError(f"Sitelink {sitelinkname} not found.")

        try:
            site = Site.get(samdb, cn=sitename)
        except ModelError as e:
            raise CommandError(e)

        if site is None:
            raise CommandError(f"Site {sitename} not found.")

        existing_sites = sitelink.siteList or []
        site_found = False
        for existing_site_dn in existing_sites:
            try:
                existing_site = Site.get(samdb, dn=existing_site_dn)
                if existing_site and existing_site.cn == sitename:
                    site_found = True
                    break
            except ModelError:
                raise CommandError(f"Unable to get existing site {existing_site}.")

        if not site_found:
            raise CommandError(f"Site {sitename} is not present in site-link {sitelinkname}")

        if len(existing_sites) <= 2:
            raise CommandError(f"Sitelink {sitelinkname} must have at least 2 sites. Cannot remove site {sitename}.")

        samdb.transaction_start()
        try:
            new_site_list = [site_dn for site_dn in existing_sites if site_dn != site.dn]
            m = ldb.Message()
            m.dn = sitelink.dn

            m["siteList"] = ldb.MessageElement(new_site_list, FLAG_MOD_REPLACE, "siteList")

            samdb.modify(m)
            
            samdb.transaction_commit()
        except Exception as e:
            samdb.transaction_cancel()
            raise CommandError(f"Error while removing site {sitename} from site-link {sitelinkname}: {e}")

        self.outf.write("Site %s removed from site-link %s!\n" % (sitename, sitelinkname))


class cmd_site_links_modify(Command):
    """Modify an existing site-link."""

    synopsis = "%prog <sitelink> [options]"

    takes_args = ["sitelinkname"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
        Option("--cost", help="Replication cost (integer value)",
               dest="cost", type=int,
               validators=[Range(NTDSSITELINK_MIN_COST, NTDSSITELINK_MAX_COST)]),
        Option("--repl-interval", help="Replication interval in minutes",
               dest="repl_interval", type=int,
               validators=[Range(NTDSSITELINK_MIN_INTERVAL, NTDSSITELINK_MAX_INTERVAL)]),
        Option("--options", help="SiteLink options bit flags (0=No options, 1=USE_NOTIFY, 2=TWO_WAY_SYNC, 4=DISABLE_COMPRESSION)",
               dest="options", type=int, default=None,
               validators=[Range(0, NTDSSITELINK_OPT_COMBINED)]),
    ]

    def run(self, sitelinkname, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, transport=None, cost=None, repl_interval=None, options=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        base_dn = SiteLink.get_base_dn(samdb, transport=transport)

        try:
            sitelink = SiteLink.get(samdb, cn=sitelinkname, base_dn=base_dn)
        except ModelError as e:
            raise CommandError(e)

        if sitelink is None:
            raise CommandError(f"Sitelink {sitelinkname} not found.")


        samdb.transaction_start()
        try:
            m = ldb.Message()
            m.dn = sitelink.dn

            if cost is not None:
                m["cost"] = ldb.MessageElement(str(cost), FLAG_MOD_REPLACE, "cost")

            if repl_interval is not None:
                m["replInterval"] = ldb.MessageElement(str(repl_interval), FLAG_MOD_REPLACE, "replInterval")

            if options is not None:
                m["options"] = ldb.MessageElement(str(options), FLAG_MOD_REPLACE, "options")

            if cost is not None or repl_interval is not None or options is not None:
                samdb.modify(m)

            samdb.transaction_commit()
        except Exception as e:
            samdb.transaction_cancel()
            raise CommandError(f"Error while modifying site-link {sitelinkname}: {e}")

        self.outf.write("Site-link %s modified successfully!\n" % sitelinkname)


class cmd_site_links_schedule_show(Command):
    """Show current site-link schedule."""

    synopsis = "%prog <sitelink> [options]"

    takes_args = ["sitelinkname"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
        Option("--show-legend", help="Show legend for schedule display",
               dest="show_legend", action="store_true", default=False),
    ]

    def run(self, sitelinkname, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, transport=None, show_legend=False):
        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        base_dn = SiteLink.get_base_dn(ldb, transport=transport)

        try:
            sitelink = SiteLink.get(ldb, cn=sitelinkname, base_dn=base_dn)
        except ModelError as e:
            raise CommandError(e)

        if sitelink is None:
            raise CommandError(f"Sitelink {sitelinkname} not found.")

        self.outf.write(f"SiteLinkName: {sitelink.cn}\n")
        self.outf.write(f"Transport: {transport}\n")
        self.outf.write(f"BandwidthDetail: \n\n")

        sitelink_schedule = ndr_pack(new_connection_schedule())
        if sitelink.schedule is not None:
            sitelink_schedule = sitelink.schedule

        schedule.show_schedule(sitelink_schedule, self.outf.write, show_legend)


class cmd_site_links_schedule_apply_preset(Command):
    """Apply predefined preset to current site-link schedule.

    Available presets:
    business_hours - Monday-Friday, 9 AM to 5 PM (4 times per hour)
    weekends       - Saturday and Sunday, all day (4 times per hour)
    all            - All days, all hours (4 times per hour)
    none           - No replication at all
    """

    synopsis = "%prog <sitelink_name> <preset> [options]"

    takes_args = ["sitelink_name", "preset"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
    ]

    def run(self, sitelink_name, preset, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, transport=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        base_dn = SiteLink.get_base_dn(samdb, transport=transport)

        try:
            sitelink = SiteLink.get(samdb, cn=sitelink_name, base_dn=base_dn)
        except ModelError as e:
            raise CommandError(e)

        if sitelink is None:
            raise CommandError(f"Sitelink {sitelink_name} not found.")

        samdb.transaction_start()
        try:
            sitelink_schedule = ndr_pack(new_connection_schedule())
            if sitelink.schedule is not None:
                sitelink_schedule = sitelink.schedule

            new_schedule = schedule.apply_schedule_preset(sitelink_schedule, preset)

            m = ldb.Message()
            m.dn = sitelink.dn
            m["schedule"] = ldb.MessageElement(new_schedule, FLAG_MOD_REPLACE, "schedule")

            samdb.modify(m)
            samdb.transaction_commit()
        except Exception as e:
            samdb.transaction_cancel()
            raise CommandError("Error assigning new schedule to site-link %s: %s" %
                               (sitelink_name, e))

        print(("New schedule has been assigned to site-link %s" %
               (sitelink_name)), file=self.outf)


class cmd_site_links_schedule_set(Command):
    """Set current site-link schedule."""

    synopsis = "%prog <sitelink_name> [options]"

    takes_args = ["sitelink_name"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--transport", help="Transport type (ip or smtp)",
               dest="transport", choices=["ip", "smtp"], default="ip"),
        Option("--days", help="List of days (1=Monday through 7=Sunday), comma-separated",
               dest="days", type=str, default=None),
        Option("--hours", help="List of hours (1-24), comma-separated",
               dest="hours", type=str, default=None),
    ]

    def run(self, sitelink_name, hostopts=None, sambaopts=None, credopts=None,
            versionopts=None, transport=None, days=None, hours=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        if days is None or hours is None:
            raise CommandError("--days and --hours must be specified")

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

        base_dn = SiteLink.get_base_dn(samdb, transport=transport)

        try:
            sitelink = SiteLink.get(samdb, cn=sitelink_name, base_dn=base_dn)
        except ModelError as e:
            raise CommandError(e)

        if sitelink is None:
            raise CommandError(f"Sitelink {sitelink_name} not found.")

        samdb.transaction_start()
        try:
            sitelink_schedule = ndr_pack(new_connection_schedule())
            if sitelink.schedule is not None:
                sitelink_schedule = sitelink.schedule

            new_schedule = schedule.set_schedule_slots(sitelink_schedule,
                                                        parsed_days,
                                                        parsed_hours,
                                                        3)

            m = ldb.Message()
            m.dn = sitelink.dn
            m["schedule"] = ldb.MessageElement(new_schedule, FLAG_MOD_REPLACE, "schedule")

            samdb.modify(m)
            samdb.transaction_commit()
        except Exception as e:
            samdb.transaction_cancel()
            raise CommandError("Error assigning new schedule to site-link %s: %s" %
                               (sitelink_name, e))

        print(("New schedule has been assigned to site-link %s" %
               (sitelink_name)), file=self.outf)


class cmd_site_links_schedule(SuperCommand):
    """Site-link schedule management subcommands."""
    subcommands = {
        "show": cmd_site_links_schedule_show(),
        "set": cmd_site_links_schedule_set(),
        "preset": cmd_site_links_schedule_apply_preset(),
    }


class cmd_sitelinks(SuperCommand):
    """Sitelink management."""
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