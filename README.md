# quartz-health-poll
Basic python script to poll QRadar for some health stats and send to a syslog destination

This came about as the SIEM does not easily forward a subset of information for monitoring
of applications. An ironic twist in that an event monitoring tool does not share it's health very
well with other platforms. Most other health platforms or log colelctions will support syslog
so this script supports a poll of stats then a push to elsewhere.

## Usage
This code sample will get you going on how to use the QRadar API to perfom actions externally to the SIEM. 

To use the script bear the following in mind:
* You will need to set a SEC token on your SIEM and change this in the config.ini file.
* If run as a cron job, file paths need to be absolute, so adjust or code in to fit.
* Three destinatiosn can be supported, although only one is used. 
* The syslog destination is on port 514 - which can be chanegd in the config.ini file.

## Health Metrics
This specific script performs an AQL query to retrieve certain health statistics for the SIEM. These
can be enabled for sending to the syslog destination by adding to the dictionary XXX. As a general 
AQL query may return many unwanted, this permits filtering to what you want to onward send.

The AQL query can be for other purposes, but the function to parse and forward would need to 
be adjusted to suit.

## Notes on Version Usage
* Tested on QRadar 7.3.2 patch 4 - against V11.0 of the App API
* Uses the older Python 2.x within the QRadar product - untested on Python 3.
