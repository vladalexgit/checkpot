import sys
import getopt
import ipaddress


def print_usage():
    """Prints correct command line usage of the app"""

    print("Usage: checkpot -t <target IP> <options>")
    print("Options: ")
    print("\t-O / --os-scan -> fingerprint OS (requires sudo)")
    print("\t-l <level> / -level= <level> -> maximum scanning level (1/2/3)")
    print("\t-p / --ports -> scan a specific range of ports (e.g. 20-100). For all ports use -p-")


def parse(argv):
    """
    Parses command line arguments and returns dict of requested options
    :param argv:
    :return:
    """

    parsed = {
        "target": None,
        "scan_os": False,
        "scan_level": 5,
        "port_range": None
    }

    short_options = 't:l:Op:'
    long_options = ['target=', 'level=', 'os-scan', 'ports']

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
