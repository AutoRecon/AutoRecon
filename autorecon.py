#!/usr/bin/env python3
#
#    AutoRecon is a network reconnaissance tool which performs automated enumeration of services.
#
#    AutoRecon is heavily based on ReconScan from RoliSoft (https://github.com/RoliSoft/ReconScan)
#    Many thanks to the authors of ReconScan for allowing the modifcation and redistribution of their code.
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU General Public License, either version 3 of the License, or (at your
#    option) any later version.
#

import re
import os
import sys
import csv
import atexit
import string
import shutil
import argparse
import threading
import subprocess
import multiprocessing
import ipaddress
import time
import json
import socket
from multiprocessing import Queue
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import concurrent.futures.thread
from libnmap.parser import NmapParser, NmapParserException
from colorama import init, Fore, Back, Style

init()

concurrent_hosts = 5
concurrent_tasks = 10
disable_quick = False

verbose     = 0
dryrun      = False
bruteforce  = True
outdir      = ''
nmapparams  = ''
hydraparams = ''
parallel    = False
hadsmb      = False
srvname     = ''
quick_ports  = '--top-ports 1000'
tcp_ports    = '-p-'
udp_ports    = '--top-ports 200'

config = None

__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, "config.json"), "r") as c:
    config = c.read()
    config = json.loads(config)

def e(*args, frame_index=1, **kvargs):
    frame = sys._getframe(frame_index)

    vals = {}

    vals.update(frame.f_globals)
    vals.update(frame.f_locals)
    vals.update(kvargs)

    return string.Formatter().vformat(' '.join(args), args, vals)

def cprint(*args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, **kvargs):
    frame = sys._getframe(frame_index)

    vals = {
        'bgreen':  Fore.GREEN  + Style.BRIGHT,
        'bred':    Fore.RED    + Style.BRIGHT,
        'bblue':   Fore.BLUE   + Style.BRIGHT,
        'byellow': Fore.YELLOW + Style.BRIGHT,

        'green':  Fore.GREEN,
        'red':    Fore.RED,
        'blue':   Fore.BLUE,
        'yellow': Fore.YELLOW,

        'bright': Style.BRIGHT,
        'srst':   Style.NORMAL,
        'crst':   Fore.RESET,
        'rst':    Style.NORMAL + Fore.RESET
    }

    vals.update(frame.f_globals)
    vals.update(frame.f_locals)
    vals.update(kvargs)

    unfmt = ''
    if char is not None:
        unfmt += color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET + sep
    unfmt += sep.join(args)

    fmted = unfmt

    for attempt in range(10):
        try:
            fmted = string.Formatter().vformat(unfmt, args, vals)
            break
        except KeyError as err:
            key = err.args[0]
            unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

    print(fmted, sep=sep, end=end, file=file)

def debug(*args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout, **kvargs):
    if verbose >= 1:
        cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def info(*args, sep=' ', end='\n', file=sys.stdout, **kvargs):
    cprint(*args, color=Fore.GREEN, char='*', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def warn(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def error(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def fail(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)
    exit(-1)

def dump_pipe(stream, stop_event=None, tag='?', color=Fore.BLUE):
    while stream.readable() and (stop_event is not None and not stop_event.is_set()):
        line = stream.readline().decode('utf-8').rstrip()

        if len(line) != 0:
            debug(color + '[' + Style.BRIGHT + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color)

def run_cmd(cmd, tag='?', redirect=None):

    if redirect is None:
        redirect = verbose >= 2

    info(('Skipping' if dryrun else 'Running') + ' task {bgreen}{tag}{rst}' + (' with {bblue}{cmd}{rst}' if verbose >= 1 else '...'))

    if dryrun:
        return True

    proc = subprocess.Popen(cmd, shell=True, stdin=None, stdout=subprocess.PIPE if redirect else subprocess.DEVNULL, stderr=subprocess.PIPE if redirect else subprocess.DEVNULL)

    if redirect:
        thdout = threading.Event()
        thderr = threading.Event()

        threading.Thread(target=dump_pipe, args=(proc.stdout, thdout, tag)).start()
        threading.Thread(target=dump_pipe, args=(proc.stderr, thderr, tag, Fore.RED)).start()

    ret = proc.wait()

    if redirect:
        thdout.set()
        thderr.set()

    if ret != 0:
        error('Task {bred}{tag}{rst} returned non-zero exit code: {ret}')
    else:
        info('Task {bgreen}{tag}{rst} finished successfully.')

    return (tag, ret)

def run_nmap_quick(address):
    scandir = os.path.abspath(os.path.join(outdir, address + srvname, 'scans'))
    run_cmd(
        e('nmap -vv --reason -sS -sV {quick_ports} --version-light {nmapparams} -oN "{scandir}/000_quick_tcp_nmap.txt" -oX "{scandir}/000_quick_tcp_nmap.xml" {address}'),
        e('nmap-quick ({address})')
    )
    return ('run_nmap_quick', e("{scandir}/000_quick_tcp_nmap.xml"))

def run_nmap_tcp(address):
    scandir = os.path.abspath(os.path.join(outdir, address + srvname, 'scans'))
    run_cmd(
        e('nmap -vv --reason -sS -A -sV -sC {tcp_ports} --osscan-guess --version-all {nmapparams} -oN "{scandir}/000_full_tcp_nmap.txt" -oX "{scandir}/000_full_tcp_nmap.xml" {address}'),
        e('nmap-tcp ({address})')
    )
    return ('run_nmap_tcp', e("{scandir}/000_full_tcp_nmap.xml"))

def run_nmap_udp(address):
    scandir = os.path.abspath(os.path.join(outdir, address + srvname, 'scans'))
    run_cmd(
        e('nmap -vv --reason -sU -A -sV -sC {udp_ports} --version-all --max-retries 1 {nmapparams} -oN "{scandir}/000_top_200_udp_nmap.txt" -oX "{scandir}/000_top_200_udp_nmap.xml" {address}'),
        e('nmap-udp ({address})')
    )
    return ('run_nmap_udp', e("{scandir}/000_top_200_udp_nmap.xml"))

def parse_nmap_services(report):
    nmap_svcs = []

    if os.path.exists(report):
        try:
            report = NmapParser.parse_fromfile(report)
            nmap_svcs += report.hosts[0].services
        except NmapParserException as ex:
            error(Fore.RED + '[' + Style.BRIGHT + 'nmap-udp ({address})' + Style.NORMAL + '] ' + Fore.RESET + 'NmapParserException: {ex}')

    return sorted(nmap_svcs, key=lambda s: s.port)

def scan_service(scandir, address, port, service, tunnel):
    secure = False
    if tunnel and ('ssl' in tunnel or 'tls' in tunnel):
        secure = True

    # Special cases for HTTP.
    scheme = 'https' if 'https' in service or 'ssl' in service or 'tls' in service or secure is True else 'http'
    nikto_ssl = ' -ssl' if 'https' in service or 'ssl' in service or 'tls' in service or secure is True else ''

    cmds = []
    for serv in config["services"]:

        ignore_service = False
        if 'nmap-service-names-ignore' in config["services"][serv]:
            for ignore in config["services"][serv]['nmap-service-names-ignore']:
                if re.match(ignore, service):
                    ignore_service = True
                    break

        if ignore_service:
            continue

        matched_service = False
        for name in config["services"][serv]['nmap-service-names']:
            if re.match(name, service):
                matched_service = True
                break

        if not matched_service:
            continue

        for command in config["services"][serv]['commands']:
            cmds.extend([
                (
                    e(command['command']),
                    e(command['tag'])
                )
            ])

    return cmds

def scan_host(address):
    info('Scanning host {byellow}{address}{rst}.')
    basedir = os.path.abspath(os.path.join(outdir, address + srvname))
    os.makedirs(basedir, exist_ok=True)

    exploitdir = os.path.abspath(os.path.join(basedir, 'exploit'))
    os.makedirs(exploitdir, exist_ok=True)

    lootdir = os.path.abspath(os.path.join(basedir, 'loot'))
    os.makedirs(lootdir, exist_ok=True)

    scandir = os.path.abspath(os.path.join(basedir, 'scans'))
    os.makedirs(scandir, exist_ok=True)

    screenshotdir = os.path.abspath(os.path.join(basedir, 'screenshots'))
    os.makedirs(screenshotdir, exist_ok=True)

    open(os.path.abspath(os.path.join(basedir, 'proof.txt')), 'a').close()

    services = []

    with ThreadPoolExecutor(max_workers=concurrent_tasks) as executor:
        futures = []

        if not disable_quick:
            futures.append(executor.submit(run_nmap_quick, address))

        futures.append(executor.submit(run_nmap_tcp, address))
        futures.append(executor.submit(run_nmap_udp, address))

        try:
            for future in as_completed(futures):
                task, *result = future.result()

                if task == 'run_nmap_quick' or task == 'run_nmap_tcp' or task == 'run_nmap_udp':
                    nmap_svcs = parse_nmap_services(result[0])
                    for service in nmap_svcs:
                        if 'open' not in service.state:
                            continue

                        tunnel = None
                        if service.tunnel:
                            tunnel = service.tunnel

                        service_tuple = (address, service.port * -1 if service.protocol == 'udp' else service.port, service.service, tunnel)
                        if service_tuple not in services:
                            services.append(service_tuple)
                        else:
                            continue

                        info('Service {bgreen}{service.port}{rst}/{bgreen}{service.protocol}{rst} is {bgreen}{service.service}{rst}' + (' running {green}' + service.service_dict['product'] + '{crst}' if 'product' in service.service_dict else '') + (' version {green}' + service.service_dict['version'] + '{crst}' if 'version' in service.service_dict else ''))

                        cmds = []
                        cmds = scan_service(scandir, *service_tuple)

                        for cmd in cmds:
                            futures.append(executor.submit(run_cmd, *cmd))

            # All Nmap scans have finished. Make sure everything else has finished.
            for future in as_completed(futures):
                future.result()

            executor.shutdown(wait=True)

        except KeyboardInterrupt:
            for future in futures:
                future.cancel()

            executor.shutdown(wait=False)
            executor._threads.clear()
            concurrent.futures.thread._threads_queues.clear()

    info("Finished scanning host {byellow}{address}{rst}.")

    return 0


if __name__ == '__main__':
    if 'COLUMNS' not in os.environ:
        os.environ['COLUMNS'] = str(shutil.get_terminal_size((80, 20)).columns)

    parser = argparse.ArgumentParser(description='Network reconnaissance tool to port scan and automatically enumerate services found on multiple hosts.')
    parser.add_argument('hosts', action='store', help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs="+")
    parser.add_argument('-ch', '--concurrent-hosts', action='store', metavar='<number>', type=int, default=5, help='The maximum number of hosts to scan concurrently. Default: %(default)s')
    parser.add_argument('-ct', '--concurrent-tasks', action='store', metavar='<number>', type=int, default=10, help='The maximum number of tasks to perform per host. Default: %(default)s')
    parser.add_argument('-dq', '--disable-quick', action='store_true', default=False, help='Disable the "quick" scan of the top 1000 TCP ports. Note that further enumeration scans won\'t start until all TCP ports have been scanned. This may cause significant delays.')
    # TODO: -r (--random) argument to sort the target list randomly.
    # TODO: -s (--service) with -p (--port) to force scan a single service.
    # TODO: --ssl flag to force SSL.
    parser.add_argument('-v', '--verbose', action='count', help='enable verbose output, repeat for more verbosity')
    parser.add_argument('-o', '--output', action='store', default='results', help='output directory for the results')
    parser.add_argument('--ports', action='store', default='-', help='port range to scan using nmap (TCP SYN only)')
    parser.add_argument('--nmap', action='store', default='-Pn -T4 --script-timeout 10m', help='additional nmap arguments')
    parser.error = lambda s: fail(s[0].upper() + s[1:])
    args = parser.parse_args()

    concurrent_hosts = args.concurrent_hosts

    if concurrent_hosts <= 0:
        fail('Argument -ch/--concurrent-hosts: must be greater or equal to 1.')

    concurrent_tasks = args.concurrent_tasks

    if concurrent_tasks <= 0:
        fail('Argument -ct/--concurrent-tasks: must be greater or equal to 1.')

    disable_quick = args.disable_quick
    outdir      = args.output
    verbose     = args.verbose if args.verbose is not None else 0
    nmapparams  = args.nmap
    srvname     = ''
    ports       = args.ports

    if ports != '-':
        quick_ports = '-p' + ports
        tcp_ports = '-p' + ports
        udp_ports = '-p' + ports

    atexit.register(lambda: os.system('stty sane'))

    if len(args.hosts) == 0:
        error('You must specify at least one host to scan!')
        sys.exit(1)

    hosts = []
    valid_hosts = True

    for host in args.hosts:
        try:
            ip = str(ipaddress.ip_address(host))

            if ip not in hosts:
                hosts.append(ip)
        except ValueError:

            try:
                host_range = ipaddress.ip_network(host, strict=False)
                if host_range.num_addresses > 256:
                    error(host + ' contains ' + str(host_range.num_addresses) + ' addresses. Split it up into smaller ranges.')
                    valid_host = False
                else:
                    for ip in host_range.hosts():
                        ip = str(ip)
                        if ip not in hosts:
                            hosts.append(ip)
            except ValueError:

                try:
                    ip = socket.gethostbyname(host)

                    if host not in hosts:
                        hosts.append(host)
                except:
                    error(host + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')
                    valid_hosts = False

    if not valid_hosts:
        sys.exit(1)

    with ProcessPoolExecutor(max_workers=concurrent_hosts) as executor:
        futures = []

        for host in hosts:
            futures.append(executor.submit(scan_host, host))

        try:
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False)

    sys.exit(0)
