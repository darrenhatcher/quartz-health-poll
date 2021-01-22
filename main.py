__author__ = 'Darren Hatcher' 
__version__ = '1.0.0'

import time
import json
import logging, logging.handlers

import urllib
import urllib2

from logging.handlers import SysLogHandler
from socket import gaierror # for tracking syslog errors

import sys
import ConfigParser 

#-------------------------------------------------------------------------------
# Pull in any utility code		 
# File for utility functions
gPoll_and_push_metrics_query = "SELECT Hostname, Metric_ID, AVG(Value) AS Avg_Value, Element FROM events WHERE LOGSOURCENAME(logsourceid) ILIKE '%%health%%'  GROUP BY Hostname, Metric_ID, Element  ORDER BY Hostname last 9 minutes"

    
# get dictionary of metrics to send
gMetrics_to_use = { "AveragePayloadSizeEvents" : "True", 
        "AveragePayloadSizeFlows" : "True", 
        "AverageRecordSizeEvents" : "True", 
        "AverageRecordSizeFlows" : "True", 
        "CREPRocessorThreadInfo" : "True", 
        "CREQueueSize" : "True", 
        "CurrentHostsTrackingCount" : "True", 
        "DiskSpaceTotal" : "True", 
        "DiskSpaceUsageMount" : "True", 
        "DiskSpaceUsed" : "True", 
        "DiskUsage" : "True", 
        "DiskWps" : "True", 
        "EventParserThreadInfo" : "True", 
        "EventRate" : "True", 
        "EventRateEPMon" : "True", 
        "LoadAvg1" : "True", 
        "LoadAvg15" : "True", 
        "LoadAvg5" : "True", 
        "PostgresCoreCPU" : "True", 
        "PostgresQradarCPU" : "True", 
        "PostgresQvmCPU" : "True", 
        "ProcessCPU" : "True", 
        "ProcessCPUTime" : "True", 
		"PostgresQvmReadIO" : "True", 
        "RunningQueries" : "True", 
        "RunningSorts" : "True", 
        "RunQueue" : "True", 
        "SysCpu" : "True", 
        "SystemCPU" : "True", 
        "SystemMemoryUsed" : "True", 
        "SystemPhysicalMemoryFree" : "True", 
        "SystemPhysicalMemoryUsed" : "True", 
        "SystemSwapMemoryUsed" : "True", 
        "TomcatCPUUsage" : "True", 
        "TomcatSessionCount" : "True", 
        "UserCpu" : "True", 
        "WorkerThreadInfo" : "True"
		}
#-------------------------------------------------------------------------------
def info_log(sMessage,sType):
	print(sType+": "+sMessage)
#-------------------------------------------------------------------------------

info_log('--------------------------------------------------------------------------------','info')
info_log('Start of Initialisation','info')
info_log('--------------------------------------------------------------------------------','info')
info_log('Version: '+__version__,'info')
#-------------------------------------------------------------------------------
#Import general purpose functions
config = ConfigParser.ConfigParser()
config.readfp(open(r'config.ini'))
SYSLOGA = config.get('base_configuration', 'DEFAULT_SYSLOG_DESTINATION_A')
SYSLOGB = config.get('base_configuration', 'DEFAULT_SYSLOG_DESTINATION_B')
SYSLOGC = config.get('base_configuration', 'DEFAULT_SYSLOG_DESTINATION_C')

#Default Primary syslog destination
if SYSLOGA != "":
    DEFAULT_SYSLOG_DESTINATION_A = SYSLOGA
    info_log('Found DEFAULT_SYSLOG_DESTINATION_A so set to: '+DEFAULT_SYSLOG_DESTINATION_A,'info')
else:
    DEFAULT_SYSLOG_DESTINATION_A = '192.168.1.55'
    info_log('DEFAULT_SYSLOG_DESTINATION_A not found so set to default: '+DEFAULT_SYSLOG_DESTINATION_A,'info')
    
#Default Primary syslog destination
if SYSLOGB != "":
    DEFAULT_SYSLOG_DESTINATION_B = SYSLOGB
    info_log('Found DEFAULT_SYSLOG_DESTINATION_B so set to: '+DEFAULT_SYSLOG_DESTINATION_B,'info')
else:
    DEFAULT_SYSLOG_DESTINATION_A = '192.168.2.91'
    info_log('DEFAULT_SYSLOG_DESTINATION_A not found so set to default: '+DEFAULT_SYSLOG_DESTINATION_A,'info')

#Default Primary syslog destination
if SYSLOGC != "":
    DEFAULT_SYSLOG_DESTINATION_C = SYSLOGC
    info_log('Found DEFAULT_SYSLOG_DESTINATION_C so set to: '+DEFAULT_SYSLOG_DESTINATION_C,'info')
else:
    DEFAULT_SYSLOG_DESTINATION_C = '192.168.3.91'
    info_log('DEFAULT_SYSLOG_DESTINATION_C not found so set to default: '+DEFAULT_SYSLOG_DESTINATION_C,'info')


#Source syslog payload to use - THIS IS THE HOSTNAME IN THE EXTERNAL SYSLOG PAYLOADS
SYSLOG_HOST = config.get('base_configuration', 'DEFAULT_SYSLOG_HOST_SEND_NAME')
if SYSLOG_HOST != "":
    DEFAULT_SYSLOG_HOST_SEND_NAME = SYSLOG_HOST
    info_log('Found DEFAULT_SYSLOG_HOST_SEND_NAME so set to: '+DEFAULT_SYSLOG_HOST_SEND_NAME,'info')
else:
    DEFAULT_SYSLOG_HOST_SEND_NAME = 'alto-qr.mrsap.org'
    info_log('DEFAULT_SYSLOG_HOST_SEND_NAME not found so set to default: '+DEFAULT_SYSLOG_HOST_SEND_NAME,'info')

#Source name put into the syslog payload (third field)
SYSLOG_SOURCE = config.get('base_configuration', 'DEFAULT_SYSLOG_SOURCE_NAME')
if SYSLOG_SOURCE != "":
    DEFAULT_SYSLOG_SOURCE_NAME = SYSLOG_SOURCE
    info_log('Found DEFAULT_SYSLOG_SOURCE_NAME so set to: '+DEFAULT_SYSLOG_SOURCE_NAME,'info')
else:
    DEFAULT_SYSLOG_SOURCE_NAME = 'QRADAR_HEALTH_FWD'
    info_log('DEFAULT_SYSLOG_SOURCE_NAME not found so set to default: '+DEFAULT_SYSLOG_SOURCE_NAME,'info')

#sec TOKEN
SEC_TOKEN = config.get('base_configuration', 'DEFAULT_SEC_TOKEN')
if SEC_TOKEN != "":
    DEFAULT_SEC_TOKEN = SEC_TOKEN
    info_log('Found DEFAULT_SEC_TOKEN so set to: '+DEFAULT_SEC_TOKEN,'info')
else:
    DEFAULT_SEC_TOKEN = 'NO TOKEN SET'
    info_log('DEFAULT_SEC_TOKEN not found! Check config.ini file and set. Is currently: '+DEFAULT_SEC_TOKEN,'info')

TARGET_SIEM_HOST = config.get('base_configuration', 'TARGET_SIEM_HOST')
if TARGET_SIEM_HOST != "":
    info_log('Found TARGET_SIEM_HOST so set to: '+TARGET_SIEM_HOST,'info')
else:
    info_log('TARGET_SIEM_HOST not found! Check config.ini file and set. Exit here.' ,'error')
    sys.exit()

# Timeout to wait until giving up on polling an Ariel search
CFG_AQL_TIMEOUT_SECONDS = config.get('base_configuration', 'AQL_TIMEOUT_SECONDS')
if CFG_AQL_TIMEOUT_SECONDS != "":
    AQL_TIMEOUT_SECONDS = int(CFG_AQL_TIMEOUT_SECONDS)
    info_log('Found AQL_TIMEOUT_SECONDS so set to: '+CFG_AQL_TIMEOUT_SECONDS,'info')
else:
    info_log('AQL_TIMEOUT_SECONDS not found! Check config.ini file and set. Exit here.' ,'error')
    sys.exit()

# Now get all the metric names supported
rawconfig = ConfigParser.RawConfigParser()
rawconfig.readfp(open(r'config.ini'))
item_list = rawconfig.items('metric_enablement')

#From that list get the enabled items from the item_list dictionary
# -----------------------------------------------------------------------------
 
# Setup log remotely ...
my_logger = logging.getLogger('MyLogger')
my_logger.setLevel(logging.INFO)

handler_A = logging.handlers.SysLogHandler(address = (str(DEFAULT_SYSLOG_DESTINATION_A),514) )
my_logger.addHandler(handler_A)

handler_B = logging.handlers.SysLogHandler(address = (str(DEFAULT_SYSLOG_DESTINATION_B),514))
my_logger.addHandler(handler_B)

handler_C = logging.handlers.SysLogHandler(address = (str(DEFAULT_SYSLOG_DESTINATION_C),514))
my_logger.addHandler(handler_C)

#send test event ...
start_message = 'Confirmation startup message from QRadar Health Polling and Forwarding app'
my_logger.info(DEFAULT_SYSLOG_HOST_SEND_NAME + ' [' + DEFAULT_SYSLOG_SOURCE_NAME + '] - ' + start_message)
info_log(start_message,'info')
info_log('Finished setting up local syslog handler/s  ...','info') 

# API endpoint for Ariel Database searches
ARIEL_SEARCHES_ENDPOINT = '/api/ariel/searches'
# JSON headers for all requests
JSON_HEADERS = {}
JSON_HEADERS['content-type'] ='application/json'
JSON_HEADERS['SEC'] = str(DEFAULT_SEC_TOKEN)   
info_log('Set JSON_HEADERS DEFAULT_SEC_TOKEN to: '+JSON_HEADERS['SEC'],'info')
info_log(json.dumps(JSON_HEADERS),'info')

# Response when a request with no response body is successful
SUCCESS_RESPONSE = {'success': 'true'}
# Response when a request with no response body fails
FAILURE_RESPONSE = {'success': 'false'}
# Response when a polling request times out
TIMEOUT_RESPONSE = {'error': 'Query timed out'}

info_log('--------------------------------------------------------------------------------','info')
info_log('End of Initialisation','info')
info_log('--------------------------------------------------------------------------------','info')

#-------------------------------------------------------------------------------
def RequestASearch():

	info_log('-->RequestASearch():','info')
	
	sPrefix = 'https://' + TARGET_SIEM_HOST + ARIEL_SEARCHES_ENDPOINT + '?query_expression='
	sSuffix = urllib2.quote(gPoll_and_push_metrics_query)
	sRequest = sPrefix + sSuffix
	#info_log("Request="+sRequest,'info')	
	req = urllib2.Request(sRequest)
	req.add_header('SEC', str(DEFAULT_SEC_TOKEN)) 
	# really important - this is a post!
	req.add_data(sSuffix)
	
	try:
		info_log('Trying:'+sRequest,'info')
		resp = urllib2.urlopen(req)
		content = resp.read()
		info_log('Normal server response','info')
		#info_log(content,'info')
		oResults = json.loads(content)
		if 'search_id' in oResults:	
			info_log('Search ID found:'+oResults['search_id'],'info')
			info_log('<--RequestASearch():','info')
			return ( oResults['search_id']  ) # as text object
		else:
			info_log('No Search ID found in search request results. Check SIEM and/or AQL used.' ,'error')
			info_log(content,'info')
			info_log('<--CollectSearchResults(sSearchId):','error')
			sys.exit()
	except urllib2.HTTPError, e:
		info_log('HTTPError = ' + str(e.code),'error')
	except urllib2.URLError, e:
		info_log('URLError = ' + str(e.reason),'error')
	except Exception:
		import traceback
		info_log('generic exception: ' + traceback.format_exc(),'error')
		
	# Ok - quit here as broken
	info_log('<--CollectSearchResults(sSearchId):','error')
	sys.exit()

    # returns either a search ID or stops with an error if it failed

#-------------------------------------------------------------------------------
def PollForResults(search_id):
    info_log('-->Entered PollForResults('+search_id+')','info')
    """
    Repeatedly call the Ariel API to check if a search has finished processing
    if it has, retrieve and return the results
    Poll only as long as the timeout defined
    """
    # Start time that the polling began at
    init_time = time.time()
    iCycleNumber = 1
    iMillSecTarget = init_time + AQL_TIMEOUT_SECONDS
    while init_time + AQL_TIMEOUT_SECONDS > time.time():
        # While within the timeout
        # Poll with an HTTP GET request to the Ariel searches endpoint specifying
        # a search to retrieve the information of
        # /api/ariel/searches/SEARCH_ID
        response = PollForSearchResults(search_id)
        if 'http_response' in response:
            # If there's an 'http_response' attribute in the response
            # the request has failed, output the response and error
            info_log('Poll request has failed, with this error code: '+response['http_response'],'error')
            sys.exit()
        if response['status'] == 'COMPLETED':
            # If the status of the query is COMPLETED, the results can now be retrieved
            # Make an HTTP GET request to the Ariel searches endpoint specifying
            # a search to retrieve the results of
            # /api/ariel/searches/SEARCH_ID/results
            response = CollectSearchResults(sSearchId)
            info_log('<--Entered PollForResults(search_id)','info')
            # Return the results as JSON object
            return response
        # Wait for 1 second before polling again to avoid spamming the API
        iTimeLeft = iMillSecTarget - time.time()
        info_log('Waiting ... cycle '+str(iCycleNumber)+'. Time left +'+str(iTimeLeft)+' sec','info')
        time.sleep(1)
        iCycleNumber = iCycleNumber + 1
		
    # If the polling has timed out, return an error
    info_log('<--PollForResults(search_id)','info')
    info_log('The search results polling has timed out and returned an error after: '+str(AQL_TIMEOUT_SECONDS)+' seconds','error')
    info_log('SIEM may be busy or similar. Increase the query time-out or review the system load.','error')
    sys.exit()
# ------------------------------------------------------------------------------
def poll_and_push_metrics(response):
    info_log('-->Entered poll_and_push_metrics()','info')

    #info_log('Response for sending:'+json.dumps(response),'info')
    iCounter = 0
    iCounterOfReducedSet = 0	
    
    for data_item in response['events']:
        iCounter = 	iCounter + 1
        if data_item['Metric_ID'] in gMetrics_to_use:
            syslog_payload =  '{ "Hostname" : "'+str(data_item['Hostname'])
            syslog_payload += '", "Metric_ID" : "'+str(data_item['Metric_ID'])
            syslog_payload += '", "Element" : "'+str(data_item['Element'])
            syslog_payload += '", "Avg_Value" : "'+str(data_item['Avg_Value'])+'" }'
            #info_log("Found - "+syslog_payload, 'info')
            info_log("Sending - "+str(data_item['Hostname'])+" "+str(data_item['Metric_ID']), 'info')
            my_logger.info(DEFAULT_SYSLOG_HOST_SEND_NAME + ' [' + DEFAULT_SYSLOG_SOURCE_NAME + '] - ' + syslog_payload)
            iCounterOfReducedSet = iCounterOfReducedSet + 1		
            time.sleep(0.02)
    syslog_payload = "Finished iterating over "+str(len(gMetrics_to_use))+" major types out of "+str(iCounterOfReducedSet)+" major/minor types from a total set of "+str(iCounter)+" results."
    info_log(syslog_payload,'info')
    time.sleep(0.5)
    my_logger.info(DEFAULT_SYSLOG_HOST_SEND_NAME + ' [' + DEFAULT_SYSLOG_SOURCE_NAME + '] - ' + syslog_payload)
    info_log('<--Finished poll_and_push_metrics()','info')
    return json.dumps(SUCCESS_RESPONSE)
#-------------------------------------------------------------------------------
def CollectSearchResults(sSearchId):
    info_log('-->CollectSearchResults('+sSearchId+'):','info')
	
    if(not sSearchId):
        info_log('Search ID not set: '+sSearchId,'error')
        sys.exit()
    else: 
        info_log('Using search ID of: '+sSearchId,'info')
		
	sRequest = 'https://'+TARGET_SIEM_HOST + ARIEL_SEARCHES_ENDPOINT+'/'+sSearchId+'/results'
	
	req = urllib2.Request(sRequest)
	req.add_header('SEC', str(DEFAULT_SEC_TOKEN)) 

	try:
		info_log('Trying:'+sRequest,'info')
		resp = urllib2.urlopen(req)
		content = resp.read()
		info_log('Normal response','info')
		# info_log(content,'info')
		return ( json.loads(content)  ) # as JSON object
	except urllib2.HTTPError, e:
		info_log('HTTPError = ' + str(e.code),'error')
	except urllib2.URLError, e:
		info_log('URLError = ' + str(e.reason),'error')
	except Exception:
		import traceback
		info_log('generic exception: ' + traceback.format_exc(),'error')
		
	# Ok - quit here as broken
    info_log('<--CollectSearchResults(sSearchId):','info')
    sys.exit()
#-------------------------------------------------------------------------------
def PollForSearchResults(sSearchId):
    info_log('-->PollForSearchResults('+sSearchId+')','info')
    if(not sSearchId):
        info_log('Search ID not set: '+sSearchId,'error')
        sys.exit()
    else: 
        info_log('Using search ID of: '+sSearchId,'info')
		
	sRequest = 'https://'+TARGET_SIEM_HOST + ARIEL_SEARCHES_ENDPOINT+'/'+sSearchId
	
	req = urllib2.Request(sRequest)
	req.add_header('SEC', str(DEFAULT_SEC_TOKEN)) 

    try:
        info_log('Trying:'+sRequest,'info')
        resp = urllib2.urlopen(req)
        content = resp.read()
        info_log('Normal response','info')
        info_log('<--PollForSearchResults(sSearchId)','info')
        # info_log(content,'info')
        oContent = json.loads(content)
        return ( oContent ) # as JSON
    except urllib2.HTTPError, e:
        info_log('HTTPError = ' + str(e.code),'error')
    except urllib2.URLError, e:
        info_log('URLError = ' + str(e.reason),'error')
    except Exception:
        import traceback
        info_log('generic exception: ' + traceback.format_exc(),'error')
		
    # Ok - quit here as broken
    info_log('Abnormal Exit','error')
    sys.exit()
#-------------------------------------------------------------------------------
# Initialise ...

# Run Search and get search ID ...
sSearchId = RequestASearch()

# If a problem
if(not sSearchId):
    info_log('Failed to request a search as no Search ID provided.','error')
    sys.exit()

# Get the search results ...
oResults = PollForResults(sSearchId)

# Now forward the results ...
poll_and_push_metrics(oResults)

# We are done
info_log('--------------------------------------------------------------------------------','info')
info_log('Finished normally','info')
info_log('--------------------------------------------------------------------------------','info')
