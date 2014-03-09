#fcex#

fcex is a python script that allows you to work with FortiClient quarantine files. 

#Usage#


    usage: fcex.py [-h] [-d] [-o] qfile

    This script can be used to extract data from a FortiClient quarantine file.

    positional arguments:
        qfile         The file FortiClient quarantine file.

    optional arguments:
        -h, --help     show this help message and exit
        -d, --details  Print the Quarantine Details
        -o, --orgname  Write file using original name.

##Examples

Display details about a sample. 

    fcex.py -d Quarantinesample

    ---- Quarantine File Summary ----

      Date Quarantined:      7/3/2014
      Time Quarantined:      13:59
      File Name:             c:\tools\eicar-sample.txt
      Threat Name:           EICAR_TEST_FILE
      SHA1:                  3395856ce81f2b7382dee72602f798b642f14140



##File Format

The quarantine file is a binary file with 2 main areas, the file header
which contains information about the file and some metadata of when it was
quarantined and the data portion which contains the obfuscated file that
was quarantine. 

The header is divided into two sections the first is a fixed length section
which contains offsets for the variable length section and information 
such as time/date of when the item was quarantined. The variable length
section contains the name and filepath of the quarantined file and the 
threat name used by the A/V.

The last area contains the obfuscated file that was quarantined 
by AV. The file is obfuscated using a simple xor AB. 


            +--------------------------------------+
            |                                      |
            |                                      |
            |           Fixed Section              |
            |                                      |
            +--------------------------------------+
            |                                      |
            |                                      |
            |                                      |
            |           Variable Section           |
            |                                      |
            |                                      |
            +--------------------------------------+
            |                                      |
            |                                      |
            |                                      |
            |           Quarantined File           |
            |                                      |
            |                                      |
            |                                      |
            |                                      |
            +--------------------------------------+

###Fixed Section

The following describes the offsets within the fixed section of the file.

 * [0:2]  Offset of quarantined file start
 * [6:8]  Year
 * [8:10] Month 
 * [12:14] Day
 * [14:16] Hour
 * [16:18] Minute
 * [36:38] Length of quarantine file name [FL]
 * [40:42] Length of threat name [TL]

###Variable Section 
 
 * [44:FL] - Name and Path of Quarantined File
 * [44+FL:44+FL+TL] - Name of threat identified by AV

##Notes

* There doesn't seem to be any information on the format that I've been able
to find, so this is based on my own observations working with this file
type. I haven't figured out all of the areas within the fixed portion, but I 
have a few assumptions on what else might be contained 
(Action taken,Checksum, Timezone,...). If you notice any issues or want to collaborate let me know 
[@seanmw](https://twitter.com/seanmw).

