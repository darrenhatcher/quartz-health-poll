# quartz-health-poll
Basic python script to poll QRadar for some health stats and send to a syslog destination

This code sample will get you going. You will need to set a SEC token on your SIEM and change this in the config.ini file.

If run as a cron job, file paths need to be absolute, so adjust or code in to fit.

Tested on QRadar 7.3.2 patch 4. 
Uses the older Python 2.x within this product.
