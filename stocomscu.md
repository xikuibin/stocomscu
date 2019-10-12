### stocomscu: DICOM Storage Commitment SCU

SYNOPSIS
========

```
stocomscu [options] peer port dcmfile-in...
```

DESCRIPTION
===========

The **stocomscu** application implements both an SCU for the N-ACTION and an SCP for N-EVENT-REPORT. **stocomscu** sends query keys to an SCP and awaits responses. It will accept associations for the purpose of receiving report sent as a result of the N-EVENT-REPORT request. The application can be used to test SCPs of the Storage Commitment Service Class. During test, DVTK Storage SCP Emulator used as test SCP.

PARAMETERS
==========
```
peer        hostname of DICOM peer

port        tcp/ip port number of peer

dcmfile-in  DICOM file or directory to be committed, whose SOP Class UIDs and SOP Instance UIds will be used as parameters.

```
OPTIONS
=======

general options
---------------
```
  -h    --help
          print this help text and exit

        --version
          print version information and exit

        --arguments
          print expanded command line arguments

  -q    --quiet
          quiet mode, print no warnings and errors

  -v    --verbose
          verbose mode, print processing details

  -d    --debug
          debug mode, print debug information

  -ll   --log-level  [l]evel: string constant
          (fatal, error, warn, info, debug, trace)
          use level l for the logger

```
network options
---------------

```

application entity titles:

  -aet  --aetitle  [a]etitle: string
          set my calling AE title (default: STORE-COM-SCU)

  -aec  --call  [a]etitle: string
          set called AE title of peer (default: STORE-COM-SCP)


port for incoming network associations:

  +P    --port  [n]umber: integer
          port number for incoming associations

other network options:

  -to   --timeout  [s]econds: integer (default: unlimited)
          timeout for connection requests

  -ta   --acse-timeout  [s]econds: integer (default: 30)
          timeout for ACSE messages

  -td   --dimse-timeout  [s]econds: integer (default: unlimited)
          timeout for DIMSE messages

  -pdu  --max-pdu  [n]umber of bytes: integer (4096..131072)
          set max receive pdu to n bytes (default: 16384)

  -dhl  --disable-host-lookup
          disable hostname lookup

        --repeat  [n]umber: integer
          repeat n times

        --abort
          abort association instead of releasing it

        --ignore
          ignore store data, receive but do not store

        --cancel  [n]umber: integer
          cancel after n responses (default: never)

  -up   --uid-padding
          silently correct space-padded UIDs

output options
--------------
 None


```

NOTES
=====

The application sends a storage commitment request, then starts to wait the SCP fro sending result in a new assocaitaion. So the two aetitle options are very important.

Known Problems
--------------
Some command options may not be corrected.

EXAMPLES
========

```
stocomscu 127.0.0.1 105 --port 115 -aet DVTK_STRC_SCU --call DVTK_STRC_SCP q.dcm
```
sends the attributes contained in the DICOM file "q.dcm" as part of a N-ACTION request to application entity DVTK_STRC_SCP on the host 127.0.0.1 at port 105. **stocomscu** itself uses the AE title DVTK_STRC_SCU. The SCP may send response (N-EVENT-REPORT) to a DVTK_STRC_SCU or a pre-configured AE based on its implementation. How the SCP interprets this request depends on its configuration. **stocomscu** will listen on part 115 for incoming associations in order to receive the committed result from the SCP.

LOGGING
=======

The level of logging output of the various command line tools and underlying libraries can be specified by the user. By default, only errors and warnings are written to the standard error stream. Using option *--verbose* also informational messages like processing details are reported. Option *--debug* can be used to get more details on the internal activity, e.g. for debugging purposes. Other logging levels can be selected using option *--log-level*. In *--quiet* mode only fatal errors are reported. In such very severe error events, the application will usually terminate. For more details on the different logging levels, see documentation of module "oflog".

COMMAND LINE
============

All command line tools use the following notation for parameters: square brackets enclose optional values (0-1), three trailing dots indicate that multiple values are allowed (1-n), a combination of both means 0 to n values.

Command line options are distinguished from parameters by a leading '+' or '-' sign, respectively. Usually, order and position of command line options are arbitrary (i.e. they can appear anywhere). However, if options are mutually exclusive the rightmost appearance is used. This behavior conforms to the standard evaluation rules of common Unix shells.

In addition, one or more command files can be specified using an '@' sign as a prefix to the filename (e.g. *@command.txt*). Such a command argument is replaced by the content of the corresponding text file (multiple whitespaces are treated as a single separator unless they appear between two quotation marks) prior to any further evaluation. Please note that a command file cannot contain another command file. This simple but effective approach allows one to summarize common combinations of options/parameters and avoids longish and confusing command lines (an example is provided in file *<datadir>/dumppat.txt*).

EXIT CODES
==========

The **stocomscu** utility uses the following exit codes when terminating. This enables the user to check for the reason why the application terminated.

general
-------

EXITCODE_NO_ERROR       0
EXITCODE__ERROR         1

ENVIRONMENT
===========

The **stocomscu** utility will attempt to load DICOM data dictionaries specified in the *DCMDICTPATH* environment variable. By default, i.e. if the *DCMDICTPATH* environment variable is not set, the file *<datadir>/dicom.dic* will be loaded unless the dictionary is built into the application (default for Windows).

The default behavior should be preferred and the *DCMDICTPATH* environment variable only used when alternative data dictionaries are required. The *DCMDICTPATH* environment variable has the same format as the Unix shell *PATH* variable in that a colon (":") separates entries. On Windows systems, a semicolon (";") is used as a separator. The data dictionary code will attempt to load each file specified in the *DCMDICTPATH* environment variable. It is an error if no data dictionary can be loaded.

SEE ALSO
========


COPYRIGHT
=========

Copyright (C) 2109 by .