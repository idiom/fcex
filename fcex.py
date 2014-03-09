#!/usr/bin/env python

import argparse 
import hashlib
import os.path
from struct import * 

class QuaratineFile:
    
    def __init__(self,qfile):   
        
        self.qfilename  = qfile
        self.rawfile    = None
        self.filestart  = None
        self.year       = None
        self.month      = None
        #self.tz         = None 
        self.day        = None
        self.hour       = None
        self.minute     = None
        self.fullname   = None
        self.filename   = None
        self.namelen    = None
        self.threatlen  = None
        self.threatname = None
        
        if not os.path.isfile(qfile):
            raise Exception('Quarantine File does not exist...')
        
        self.rawfile = open(qfile,'rb').read()
        self.filestart = unpack('<h',self.rawfile[0:2])[0]
        
        self.year = unpack('<h',self.rawfile[6:8])[0]
        self.month = unpack('<h',self.rawfile[8:10])[0]
        #self.tz = unpack('<h',self.rawfile[10:12])[0] #maybe?
        self.day = unpack('<h',self.rawfile[12:14])[0]
        self.hour = unpack('<h',self.rawfile[14:16])[0]
        self.minute = unpack('<h',self.rawfile[16:18])[0]        
        self.namelen = unpack('<h',self.rawfile[36:38])[0]
        self.threatlen = unpack('<h',self.rawfile[40:42])[0]
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
        qobj += " Date Quarantined:      %d/%d/%d\n" % (self.day,self.month,self.year)
        qobj += " Time Quarantined:      %d:%02d\n" % (self.hour,self.minute)
        qobj += " File Name:             %s\n" % self.fullname 
        qobj += " Threat Name:           %s\n" % self.threatname        
        m = hashlib.sha1() 
        m.update(self.extractfile())
        qobj += " SHA1:                  %s\n" % m.hexdigest()  
        
        
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

