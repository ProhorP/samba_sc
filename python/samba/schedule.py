# python schedule manipulation code
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

"""Manipulating schedules."""

import ldb
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, LdbError
import datetime

from samba.dcerpc import drsblobs
from samba.ndr import ndr_unpack, ndr_pack

from samba.kcc.kcc_utils import new_connection_schedule
from samba.domain.models.connection import NTDSCONN_OPT_IS_GENERATED, NTDSCONN_OPT_USER_OWNED_SCHEDULE


def get_utc_offset_hours():
    """
    Get the current system's UTC offset in hours as a float.
    
    Returns:
        int: UTC offset in hours (positive for UTC+X, negative for UTC-X)
    """
    now = datetime.datetime.now()
    utc_now = datetime.datetime.utcnow()
    delta = utc_now - now
    return int(delta.total_seconds() // 3600.0)


class ScheduleException(Exception):
    """Base element for Schedule errors"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%s: %s" % (self.__class__.__name__, self.value)

class ScheduleInvalidArgumentException(ScheduleException):
    """Raised when invalid arguments are provided to a schedule function."""

class ConnectionNotFound(ScheduleException):
    """Raised when connection does not exist."""
    pass


def show_schedule(schedule, outf_write, print_legend=False):
    """
    Display a replication schedule in a tabular format.

    :param schedule: A SCHEDULE Structure with Size, Bandwidth, NumberOfSchedules,
                     Schedules array, and Data field containing 168 bytes of time slots
    :param outf_write: Function that prints output to stdout similar to print
    :param print_legend: If we want to show user a legend
    """

    schedule_data = ndr_unpack(drsblobs.schedule, schedule).dataArray[0].slots

    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    outf_write("┌─" + ("─" * 2 + "┬") * 24 + "──" + "┐\n")
    header = "│D\\H│"
    for hour in range(1, 25):
        header += f"{hour:02d}│"
    outf_write(f"{header}\n")
    outf_write("├─" + ("─" * 2 + "┼") * 24 + "──" + "┤\n")

    for day_idx, day_name in enumerate(days):
        day_row = f"│{day_name}│"

        for hour in range(24):
            byte_pos = (day_idx * 24 + hour + get_utc_offset_hours()) % len(schedule_data)

            symbol = "  "

            if byte_pos < len(schedule_data):
                byte_val = schedule_data[byte_pos]

                # Check which bits are set (lower 4 bits only)
                enabled_intervals = byte_val & 0x0F

                if enabled_intervals == 0x00:
                    symbol = "  "  # None
                elif enabled_intervals == 0x01:
                    symbol = "░░"  # Once per Hour (only first interval)
                elif enabled_intervals == 0x05:
                    symbol = "▒▒"  # Twice per Hour (first and third intervals)
                elif enabled_intervals == 0x0F:
                    symbol = "▓▓"  # Four Times per Hour (all intervals)
            else:
                print(len(schedule_data), byte_pos)

            day_row += symbol + "│"

        outf_write(f"{day_row}\n")
        if day_idx != 6:
            outf_write("├─" + ("─" * 2 + "┼") * 24 + "──" + "┤\n")

    outf_write("└─" + ("─" * 2 + "┴") * 24 + "──" + "┘\n\n")

    if print_legend:
        outf_write("Legend:\n\n")
        outf_write("[  ] - None (0x00)\n")
        outf_write("[░░] - Once per Hour (0x01)\n")
        outf_write("[▒▒] - Twice per Hour (0x05)\n")
        outf_write("[▓▓] - Four Times per Hour (0x0f)\n")

def set_schedule_slot(schedule, day, hour, slot):
    """
    Set or clear a specific 15-minute time slot in the schedule.

    :param schedule: A SCHEDULE Structure with Size, Bandwidth, NumberOfSchedules,
                         Schedules array, and Data field containing 168 bytes of time slots
    :param day: Day of week (1=Monday through 7=Sunday)
    :param hour: Hour (1-24)
    :param slot: Amount of replication per hour (must be 0, 1, 2, or 3)

    Returns:
        bytes: The updated schedule
    """
    if day < 1 or day > 7:
        raise ScheduleInvalidArgumentException("Day must be between 1 (Monday) and 7 (Sunday)")

    if hour < 1 or hour > 24:
        raise ScheduleInvalidArgumentException("Hour must be between 1 and 24")

    if slot < 0 or slot > 3:
        raise ScheduleInvalidArgumentException("Slot must be between 0 and 3")

    if schedule is None:
        schedule = new_connection_schedule()

    unpacked_schedule = ndr_unpack(drsblobs.schedule, schedule)

    schedule_data = unpacked_schedule.dataArray[0].slots

    day_index = day - 1
    hour_index = hour - 1
    data_index = (day_index * 24 + hour_index + get_utc_offset_hours()) % len(schedule_data)

    slot_values = [0x00, 0x01, 0x05, 0x0F]
    new_value = slot_values[slot]

    schedule_data[data_index] = new_value

    data = drsblobs.scheduleSlots()
    data.slots = schedule_data

    unpacked_schedule.dataArray = [data]

    return ndr_pack(unpacked_schedule)


def set_schedule_slots(schedule, days, hours, slot):
    """
    Set or clear 15-minute time slots for multiple day/hour combinations in the schedule.

    :param schedule: A SCHEDULE Structure with Size, Bandwidth, NumberOfSchedules,
                     Schedules array, and Data field containing 168 bytes of time slots
    :param days: List of days of week (1=Monday through 7=Sunday)
    :param hours: List of hours (1-24)
    :param slot: Amount of replication per hour (must be 0, 1, 2, or 3)

    Returns:
        bytes: The updated schedule
    """
    if not isinstance(days, list) or not days:
        raise ScheduleInvalidArgumentException("Days must be a non-empty list")

    if not isinstance(hours, list) or not hours:
        raise ScheduleInvalidArgumentException("Hours must be a non-empty list")

    if schedule is None:
        schedule = new_connection_schedule()

    for day in days:
        for hour in hours:
            schedule = set_schedule_slot(schedule, day, hour, slot)

    return schedule

def apply_schedule_preset(schedule, preset_name):
    """
    Apply a preset schedule pattern.

    :param schedule: A SCHEDULE Structure with Size, Bandwidth, NumberOfSchedules,
                     Schedules array, and Data field containing 168 bytes of time slots
    :param preset_name: Preset name - "business_hours", "weekends",
                        "off_hours", "all", or "none"

    Returns:
        bytes: The updated schedule
    """
    # No replication at all
    days = list(range(1, 8))
    hours = list(range(1, 25))
    schedule = set_schedule_slots(schedule, days, hours, 0)

    if preset_name == "business_hours":
        # Monday-Friday, 9 AM to 5 PM (hours 9-17)
        days = list(range(1, 6))
        hours = list(range(9, 18))
        return set_schedule_slots(schedule, days, hours, 3)

    elif preset_name == "weekends":
        # Saturday and Sunday, all day
        days = [6, 7]
        hours = list(range(1, 25))
        return set_schedule_slots(schedule, days, hours, 3)

    elif preset_name == "off_hours":
        # Monday-Friday, evening and night (6 PM to 8 AM)
        days = list(range(1, 6))
        hours = list(range(18, 25)) + list(range(1, 9))
        return set_schedule_slots(schedule, days, hours, 2)

    elif preset_name == "all":
        # All days, all hours
        days = list(range(1, 8))
        hours = list(range(1, 25))
        return set_schedule_slots(schedule, days, hours, 3)

    elif preset_name == "none":
        return schedule

    else:
        raise ScheduleInvalidArgumentException(f"Unknown preset name: {preset_name}")

def set_connection_schedule(samdb, connection, schedule):
    """Assign a new schedule to a connection.

    :param samdb: A samdb connection
    :param connection: Name of the connection
    :return: None
    """
    m = ldb.Message()
    m.dn = connection.dn

    if connection.options is not None:
        current_options = connection.options
        new_options = (current_options & ~NTDSCONN_OPT_IS_GENERATED) | NTDSCONN_OPT_USER_OWNED_SCHEDULE
        m["options"] = ldb.MessageElement(str(new_options), FLAG_MOD_REPLACE,
                                           "options")
    
    m["schedule"] = ldb.MessageElement(schedule, FLAG_MOD_REPLACE,
                                        "schedule")
    samdb.modify(m)
