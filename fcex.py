#!/usr/bin/env python

import argparse 
import hashlib
import os.path
from struct import * 

class QuaratineFile:
    
    #Weekday 0 -- 6
    #The day of the week, Sunday=0, Monday=1 ... Saturday=6
    weekdays = {
        0x0: "Sunday",
        0x1: "Monday",
        0x2: "Tuesday",
        0x3: "Wednesday",
        0x4: "Thursday",
        0x5: "Friday",
        0x6: "Saturday",
    }
    
    def __init__(self,qfile):   
        
        self.qfilename  = qfile
        self.rawfile    = None
        self.filestart  = None
        self.year       = None
        self.month      = None
        self.weekday    = None 
        self.day        = None
        self.hour       = None
        self.minute     = None
        self.second     = None
        self.millisec   = None
        self.fullname   = None
        self.filename   = None
        self.namelen    = None
        self.threatlen  = None
        self.threatname = None
        
        if not os.path.isfile(qfile):
            raise Exception('Quarantine File does not exist...')
        
        self.rawfile = open(qfile,'rb').read()
        self.filestart = unpack('<H',self.rawfile[0:2])[0]
        self.year = unpack('<H',self.rawfile[6:8])[0]
        self.month = unpack('<H',self.rawfile[8:10])[0]
        self.weekday = unpack('<H',self.rawfile[10:12])[0]
        self.day = unpack('<H',self.rawfile[12:14])[0]
        self.hour = unpack('<H',self.rawfile[14:16])[0]
        self.minute = unpack('<H',self.rawfile[16:18])[0]
        self.second = unpack('<H',self.rawfile[18:20])[0]  
        self.millisec = unpack('<H',self.rawfile[20:22])[0]          
        self.namelen = unpack('<H',self.rawfile[36:38])[0]
        self.threatlen = unpack('<H',self.rawfile[40:42])[0]
        self.fullname = self.rawfile[44:44+self.namelen]
        self.filename = self.fullname.split('\\')[-1].replace('\0','')
        crsr = 44+self.namelen
        self.threatname = self.rawfile[crsr:crsr+self.threatlen]

            
    def extractfile(self, decrypt=True):
        
        data = bytearray(self.rawfile[self.filestart:])
        if not decrypt:
            return data
        for x in range(0,len(data)):
            data[x] ^= 0xAB        
        return data
        
    def __repr__(self):
        qobj = "\n\n"
        qobj += "---- Quarantine File Summary ----\n"
        qobj += "\n"
        qobj += " Date Quarantined:      %s, %d/%d/%d %d:%02d:%02d.%03d  \n" \
        % (self.weekdays[self.weekday], self.day,self.month, self.year, self.hour, self.minute,self.second,self.millisec)
        qobj += " File Name:             %s\n" % self.fullname 
        qobj += " Threat Name:           %s\n" % self.threatname        
        m = hashlib.sha1() 
        m.update(self.extractfile())
        qobj += " SHA1 Hash:             %s\n" % m.hexdigest()  
        
        qobj += "\n"
        return qobj

def main():
    parser = argparse.ArgumentParser(description="This script can be used to extract data from a FortiClient quarantine file.")
    parser.add_argument("qfile", help="The file that you wish to extract the sample from.")    
    parser.add_argument('-d','--details',dest='details',action='store_true',help="Print the Quarantine Details ")
    parser.add_argument('-o','--orgname', dest='orgname',action='store_true',help="Write file using original name.")

    args = parser.parse_args()
    
    q = QuaratineFile(args.qfile)
    
    if args.details:
        print q
    else:
        filedata = q.extractfile()
        fname = 'sample.bin'
        if args.orgname:
            fname = q.filename
        outf = open(fname,'wb')
        outf.write(filedata) 
        outf.close()
    
    return 0

if __name__ == '__main__':

    main()

