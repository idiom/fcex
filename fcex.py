#!/usr/bin/env python

__description__ = 'Library to work with FortiClient Quarantine Files'
__author__ = 'Sean Wilson'
__version__ = '0.0.2'

'''
 --- History ---
 3.9.2014  - Initial Release
 2.24.2015 - Updated Field parsing
 4.29.2015 - Added Setup.py

'''

import argparse 
import hashlib
import os.path
from struct import *
from datetime import datetime


class FCQuaratineFile:
    
    # Weekday 0 -- 6
    # The day of the week, Sunday=0, Monday=1 ... Saturday=6
    weekdays = {
        0x0: "Sunday",
        0x1: "Monday",
        0x2: "Tuesday",
        0x3: "Wednesday",
        0x4: "Thursday",
        0x5: "Friday",
        0x6: "Saturday",
    }
    
    def __init__(self, qfile):
        
        self.qfilename = qfile
        
        if not os.path.isfile(qfile):
            raise Exception('Quarantine File does not exist...')
        
        self.rawfile = open(qfile, 'rb').read()
        self.filestart = unpack('<I', self.rawfile[0:4])[0]
        self.year = unpack('<H', self.rawfile[6:8])[0]
        self.month = unpack('<H', self.rawfile[8:10])[0]
        self.weekday = unpack('<H', self.rawfile[10:12])[0]
        self.day = unpack('<H', self.rawfile[12:14])[0]
        self.hour = unpack('<H', self.rawfile[14:16])[0]
        self.minute = unpack('<H', self.rawfile[16:18])[0]
        self.second = unpack('<H', self.rawfile[18:20])[0]
        self.millisec = unpack('<I', self.rawfile[20:24])[0]
        self.date = datetime(self.year, self.month, self.day, self.hour, self.minute, self.second, self.millisec)
        self.namelen = unpack('<I', self.rawfile[36:40])[0]
        self.threatlen = unpack('<I', self.rawfile[40:44])[0]
        self.fullname = self.rawfile[44:44+self.namelen]
        self.filename = self.fullname.split('\\')[-1].replace('\0', '')
        crsr = 44+self.namelen
        self.threatname = self.rawfile[crsr:crsr+self.threatlen]

    def calchash(self, htype):
        fdat = self.extractfile()
        if htype == 'md5':
            m = hashlib.md5()
        elif htype == 'sha1':
            m = hashlib.sha1()
        elif htype == 'sha256':
            m = hashlib.sha256()
        m.update(fdat)
        return m.hexdigest()

    def extractfile(self, decrypt=True):
        
        data = bytearray(self.rawfile[self.filestart:])
        if not decrypt:
            return data
        for x in range(0, len(data)):
            data[x] ^= 0xAB        
        return data
        
    def __repr__(self):
        qobj = "\n\n"
        qobj += "---- Quarantine File Summary ----\n"
        qobj += "\n"
        qobj += " Date Quarantined:   %s\n" % self.date
        qobj += " File Name:          %s\n" % self.fullname
        qobj += " Threat Name:        %s\n" % self.threatname
        qobj += " MD5 Hash:           %s\n" % self.calchash('md5')
        qobj += " SHA1 Hash:          %s\n" % self.calchash('sha1')
        qobj += " SHA256 Hash:        %s\n" % self.calchash('sha256')
        
        qobj += "\n"
        return qobj

def main():
    parser = argparse.ArgumentParser(description="Python Library to work with FortiClient Quarantine Files.")
    parser.add_argument("qfile", help="The file that you wish to extract the sample from.")    
    parser.add_argument('-d', '--details', dest='details', action='store_true', help="Print the Quarantine Details ")
    parser.add_argument('-o', '--orgname', dest='orgname', action='store_true', help="Write file using original name.")

    args = parser.parse_args()
    
    q = FCQuaratineFile(args.qfile)
    
    if args.details:
        print q
    else:
        filedata = q.extractfile()

        if args.orgname:
            fname = q.filename
        else:
            fname = q.calchash('md5')

        outf = open(fname, 'wb')
        outf.write(filedata) 
        outf.close()
    return 0

if __name__ == '__main__':

    main()

