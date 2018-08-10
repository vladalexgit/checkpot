# Checkpot - Honeypot Checker
# Copyright (C) 2018  Vlad Florea
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# DISCLAIMER: All prerequisites (containers, additional programs, etc.)
# and libraries that might be needed to run this program are property
# of their original authors and carry their own separate licenses that
# you should read to inform yourself about their terms.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# As this software is PROVIDED WITH ABSOLUTELY NO WARRANTY OF ANY KIND,
# YOU USE THIS SOFTWARE AT YOUR OWN RISK!
#
# By using this tool YOU TAKE FULL LEGAL RESPONSIBILITY FOR ANY
# POSSIBLE OUTCOME.
#
# We strongly recommend that you read all the information in the README.md
# file (found in the root folder of this project) and even the
# documentation (which you can find locally in the /docs/ folder or
# at http://checkpot.readthedocs.io/) to make sure you fully
# understand how this tool works and consult all laws that apply
# to your use case.
#
# We strongly suggest that you keep this notice intact for all files.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# The local copy of the license should be located in the root folder of the app
# in the file gpl-3.0.txt.
#
# You can contact the author and team at any time via the Checkpot official
# GitHub page: https://github.com/honeynet/checkpot or via the Honeynet
# official Slack channel: https://gsoc-slack.honeynet.org/ or
#                         https://honeynetpublic.slack.com/
#
# You can contact us at any time and with any question, we are here to help!
#
# If you consider any information in this copyright notice might be incorrect,
# outdated, arises any questions, raises any problems, etc. please contact us
# and we will make it our top priority to fix it. We have the deepest respect
# for the work of all authors and for all of our users.

import getopt
import ipaddress


def print_usage():
    """Prints correct command line usage of the app"""

    print("Usage: checkpot -t <target IP> <options>")
    print("Options: ")
    print("\t-O / --os-scan -> fingerprint OS (requires sudo)")
    print("\t-l / --level= <level> -> maximum scanning level (1/2/3)")
    print("\t-p / --ports <port range> -> scan a specific range of ports (e.g. 20-100)."
          " For all ports use -p -")
    print("\t-f / --fast -> Uses -Pn and -T5 for faster scans on local connections")
    print("\t-s / --show <c/w> -> Show copyright/warranty information")


def parse(argv):
    """
    Parses command line arguments and returns dict of requested options

    :param argv:
    :return: options dict
    """

    parsed = {
        "target": None,
        "scan_os": False,
        "scan_level": 5,
        "port_range": None,
        "fast": False
    }

    short_options = 't:l:Op:fs:'
    long_options = ['target=', 'level=', 'os-scan', 'ports', 'fast', 'show=']

    try:
        options, values = getopt.getopt(argv[1:], short_options, long_options)
    except getopt.GetoptError as opt_error:
        print(opt_error)
        print_usage()
        return None

    for option, value in options:

        if option in ('-t', '--target'):
            parsed["target"] = value
        elif option in ('-l', '--level'):
            parsed["scan_level"] = int(value)
        elif option in ('-O', '--osscan'):
            parsed["scan_os"] = True
        elif option in ('-p', '--ports'):
            parsed["port_range"] = value
        elif option in ('-f', '--fast'):
            parsed["fast"] = True
        elif option in ('-s', '--show'):
            if value == 'c':
                pass
            elif value == 'w':
                print("THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY\n"
                        "APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT\n"
                        'HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY\n'
                        "OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,\n"
                        "THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR\n"
                        "PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM\n"
                        "IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF\n"
                        "ALL NECESSARY SERVICING, REPAIR OR CORRECTION.\n"
                        "\n"
                        "IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING\n"
                        "WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS\n"
                        "THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY\n"
                        "GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE\n"
                        "USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF\n"
                        "DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD\n"
                        "PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),\n"
                        "EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF\n"
                        "SUCH DAMAGES.\n"
                      )

            exit(0)

    # validate target
    # TODO convert this to use exceptions if it gets too big

    if parsed["target"] is None:
        print("No target specified. Use -t")
        print_usage()
        return None

    try:
        ipaddress.ip_address(parsed["target"])
    except ValueError:
        # not a valid ip address
        print("Target not a valid IP address")
        print_usage()
        return None

    return parsed
