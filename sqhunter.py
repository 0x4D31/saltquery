#!/usr/bin/env python

import salt.client
import argparse
import json
from cymon import Cymon
from netaddr import *

__author__ = 'Adel "0x4d31" Ka'
__version__ = '0.1'

# Cymon.io API Key
cymon_api_key = "fj5n92xr89zd8s3a5ks02a4xz9EXAMPLE"


ASCII = r"""
               __                __           
   _________ _/ /_  __  ______  / /____  _____
  / ___/ __ `/ __ \/ / / / __ \/ __/ _ \/ ___/
 (__  ) /_/ / / / / /_/ / / / / /_/  __/ /    
/____/\__, /_/ /_/\__,_/_/ /_/\__/\___/_/     
        /_/                                   
 threat hunter based on osquery and salt open  
==============================================

"""

predefinedQueries = {
    'open_sockets': 'select p.pid, p.name, p.cmdline, o.local_address, \
                     o.remote_address, o.local_port, o.remote_port, family, \
                     protocol from process_open_sockets o, processes p on \
                     o.pid = p.pid where family = 2 and (local_port and \
                     remote_port <> 0);',
    'listening_ports': 'select l.address, l.port, p.name, p.path, p.cmdline, \
                        p.uid, u.username, family, protocol from \
                        listening_ports l, processes p, users u where l.pid = \
                        p.pid AND p.uid = u.uid;',
    'root_logins': 'select * from last where username = "root" and \
                           time > ((select unix_time from time) - 3600);'
}


def saltquery(hosts, module, query):
    client = salt.client.LocalClient()
    eform = "glob" if '*' in hosts else "list"
    result = client.cmd(hosts, module, [query], expr_form=eform)
    return result


def threat_checker(ip):
    if not IPAddress(ip).is_private():
        api = Cymon(cymon_api_key)
        result = api.ip_events(ip)
        if result['count'] != 0:
            return result
    return None


def hunter(res):
    for host, value in res.iteritems():
        msock = 0
        if value['result']:
            for i in value['data']:
                resp = threat_checker(i['remote_address'])
                if resp:
                    msock += 1
                    alerttext = ("\n[+] Alert - Host: {}\n\n"
                                 "    + Process and network socket info:\n"
                                 "        - pid: {}\n"
                                 "        - name: {}\n"
                                 "        - cmdline: {}\n"
                                 "        - local_address: {}\n"
                                 "        - local_port: {}\n"
                                 "        - remote_address: {}\n"
                                 "        - remote_port: {}\n"
                                 "        - protocol: {}")
                    print alerttext.format(host,
                                           i['pid'],
                                           i['name'],
                                           i['cmdline'],
                                           i['local_address'],
                                           i['local_port'],
                                           i['remote_address'],
                                           i['remote_port'],
                                           i['protocol'])
                    print "    + Threat reports:"
                    for r in resp['results']:
                        threattext = ("        - title: {}\n"
                                      "          date: {}\n"
                                      "          details_url: {}\n"
                                      "          tag: {}")
                        print threattext.format(r['title'],
                                                r['updated'],
                                                r['details_url'],
                                                r['tag'])
        if msock == 0:
            print "+ Nothing found on {}!".format(host)


def main():
    parser = argparse.ArgumentParser(usage='sqhunter.py [Options] {target}')

    parser.add_argument('target',
                        type=str,
                        help="target hosts. Bash glob (e.g. 'prod-db*') or \
                              list of hosts (e.g. 'host1,host2')")

    parser.add_argument('-oS', '--open-sockets',
                        action="store_true",
                        help="predefined query: open network sockets")

    parser.add_argument('-lP', '--listening-ports',
                        action="store_true",
                        help="predefined query: processes with listening port")

    parser.add_argument('-qP', '--query-packs',
                        type=str,
                        help="queries from the default query packs: \
                              https://osquery.io/docs/packs/")

    parser.add_argument('-q', '--query',
                        type=str,
                        help="custom query to run")

    parser.add_argument('-t', '--threatintel',
                        action="store_true",
                        help="check the result against threat intel sources. \
                              use it with -oS")

    parser.add_argument('-p', '--print-result',
                        action="store_true",
                        help="print the result")

    args = parser.parse_args()
    # open_sockets query
    if args.open_sockets:
        fquery = predefinedQueries.get('open_sockets')
        queryres = saltquery(args.target,
                             'osquery.query',
                             fquery)
        # threat intelligence
        if args.threatintel and queryres:
            hunter(queryres)
    # listening_ports query
    elif args.listening_ports:
        fquery = predefinedQueries.get('listening_ports')
        queryres = saltquery(args.target,
                             'osquery.query',
                             fquery)
    # custom query
    elif args.query:
        queryres = saltquery(args.target,
                             'osquery.query',
                             args.query)
    # default query packs
    # some queries are not implemented. Check the following links:
    #  https://github.com/saltstack/salt/blob/develop/salt/modules/osquery.py
    #  https://docs.saltstack.com/en/latest/ref/modules/all/salt.modules.osquery.html
    elif args.query_packs:
        queryres = saltquery(args.target,
                             'osquery.{}'.format(args.query_packs),
                             '')
    else:
        print "+ No query to run!"
    # print query results
    if args.print_result:
        print json.dumps(queryres, indent=4, sort_keys=True)


if __name__ == '__main__':
    print('\n'.join(ASCII.splitlines()))
    main()
