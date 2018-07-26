import time
import sys
import subprocess


from containers.manager import Manager

manager = Manager()


def honeypot_test(container_name, port_range=None):
    """
    Starts a container and runs nmap scan

    :param container_name: target container
    :param port_range: specify a custom port range for scan (e.g '20-100')
    """

    manager.start_honeypot(container_name)

    time.sleep(10)  # TODO wait for container to start, catch some sort of signal

    print("Collecting data ...")

    args = ['nmap', manager.get_honeypot_ip(container_name) + ' -sV -n']

    if port_range:
        args = ['nmap', manager.get_honeypot_ip(container_name) + ' -p' + port_range + ' -sV -n']

    print(args)

    p = subprocess.Popen(args,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    (nmap_stdout, nmap_err) = p.communicate()

    nmap_stdout = bytes.decode(nmap_stdout)
    nmap_err = bytes.decode(nmap_err)

    with open("nmap_scan_all.out", 'a') as f:
        f.write(container_name+"\n")
        f.write(nmap_stdout)
    with open("nmap_scan_all.err", 'a') as f:
        f.write(container_name + "\n")
        f.write(nmap_err)

    args = ['nmap', '-oX', '-', manager.get_honeypot_ip(container_name) + ' -sV -n']

    if port_range:
        args = ['nmap', '-oX', '-', manager.get_honeypot_ip(container_name) + ' -p' + port_range + ' -sV -n']

    print(args)

    p = subprocess.Popen(args,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    (nmap_stdout, nmap_err) = p.communicate()

    nmap_stdout = bytes.decode(nmap_stdout)
    nmap_err = bytes.decode(nmap_err)

    with open("_batch_scan_"+container_name+".xml", 'w') as f:
        f.write(nmap_stdout)
    with open("_batch_scan_"+container_name+".err", 'w') as f:
        f.write(nmap_err)

    manager.stop_honeypot(container_name)


def main():
    """
    Entry point for the Continuous Integration tools.
    Write all tests here.
    """

    # test amun
    honeypot_test('amun', port_range='-')

    # test artillery
    honeypot_test('artillery', port_range='-')

    # test beartrap
    honeypot_test('beartrap')

    # test conpot
    honeypot_test('conpot', port_range='0-501,503-1000')

    # test cowrie
    honeypot_test('cowrie', port_range='-')

    # test dionaea
    honeypot_test('dionaea', port_range='-')

    # test glastopf
    honeypot_test('glastopf')

    # test honeypy
    honeypot_test('honeypy', port_range='-')

    # test dionaea
    honeypot_test('honeything')

    # test honeytrap
    honeypot_test('honeytrap', port_range='-')

    # test kippo
    honeypot_test('kippo', port_range='-')

    # test mtpot
    honeypot_test('mtpot')

    # test shockpot
    honeypot_test('shockpot', port_range='-')

    # test telnetlogger
    honeypot_test('telnetlogger')


if __name__ == '__main__':
    main()
