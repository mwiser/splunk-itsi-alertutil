import subprocess
import uuid
import sys
import urllib2
import json
from pyhec import PyHEC
import random, string
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
returnv=""
correlatorids=[]
AuthToken = "DB6C9B5D-1970-4BE4-8B13-3185B6C63075"
HOST = "localhost"
PORT = 8089
USERNAME = "admin"
PASSWORD = "changeme"

def checkKVStore (groupeventId):
	print ("Checking KV Store for:"+groupeventId)
	urlstring = "https://"+HOST+":8089/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group/"+groupeventId
	print urlstring
	output = (requests.get(urlstring, verify=False, auth=(USERNAME, PASSWORD)))
	#print output
	return output
def updateKVStoreSeveritySingleEvent (inputstring,eventId):
	print ("About to update event:"+eventId)
	urlstring = "https://"+HOST+":8089/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event/"+eventId+"/?is_partial_data=1"
	event = {inputstring}
	payload = {"host": urlstring,"severity": inputstring}
	r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
	return r
def updateKVStoreStatusSingleEvent (inputstring,eventId):
	print ("About to update event:"+eventId)
	urlstring = "https://"+HOST+":8089/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event/"+eventId+"/?is_partial_data=1"
	event = {inputstring}
	payload = {"host": urlstring,"status": inputstring}
	r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
	return r
def updateKVStoreSeverity (inputstring,groupeventId):
	print ("About to update event:"+groupeventId)
	urlstring = "https://"+HOST+":8089/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group/"+groupeventId+"/?is_partial_data=1"
	event = {inputstring}
	payload = {"host": urlstring,"severity": inputstring}
	r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
	resultset = getEventsforEventGroup(groupeventId)
	for singleresult in resultset:
		print ("Updating single event:"+singleresult)
		updateKVStoreSeveritySingleEvent (inputstring,singleresult)
	return r
def getEventsforEventGroup (groupeventId):
        import splunklib.results as results
        import splunklib.client as client
        arr = []

        # Create a Service instance and log in
        service = client.connect(
    host=HOST,
    port=PORT,
    username=USERNAME,
    password=PASSWORD)

        kwargs_oneshot = {}
        searchquery_oneshot = "search index=itsi_grouped_alerts "+groupeventId+" |dedup event_id|table event_id"
        print (searchquery_oneshot)
        oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)

        # Get the results and display them using the ResultsReader
        reader = results.ResultsReader(oneshotsearch_results)
        #print "Found individual events:"+str(len(reader))
        for item in reader:
                row = item.values()
                #print("Updating EventId:"+row[0])
                arr.append(row[0])
	return arr
def updateKVStoreStatus (inputstring,groupeventId):
	print ("About to update event:"+groupeventId)
	urlstring = "https://"+HOST+":8089/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group/"+groupeventId+"/?is_partial_data=1"
	event = {inputstring}
	payload = {"host": urlstring,"status": inputstring}
	r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
	resultset = getEventsforEventGroup(groupeventId)
	for singleresult in resultset:
		print ("Updating single event:"+singleresult)
		updateKVStoreStatusSingleEvent (inputstring,singleresult)
	return r
#rint (str(len(sys.argv)))

if len(sys.argv) != 3 and len(sys.argv) != 4:
	print "usage: python alertutil.py closealerts \"<query>\""
	print "usage: python alertutil.py setstatus \"<eventid>\" statusvalue"
	print "usage: python alertutil.py setseverity \"<eventid>\" severityvalue"
	sys.exit(0)

if ((len(sys.argv)==4) and ("setseverity" in sys.argv[1])):
	groupeventId = sys.argv[2]
	severityvalue = sys.argv[3]
	print ("Setting event:"+groupeventId+" to:"+severityvalue)
	returnval = checkKVStore(groupeventId)
	print returnval
	returnval = updateKVStoreSeverity (severityvalue,groupeventId)
	print returnval
	sys.exit(0)

if ((len(sys.argv)==4) and ("setstatus" in sys.argv[1])):
	groupeventId = sys.argv[2]
	statusvalue = sys.argv[3]
	print ("Setting event:"+groupeventId+" to:"+statusvalue)
	returnval = checkKVStore(groupeventId)
	print returnval
	returnval = updateKVStoreStatus (statusvalue,groupeventId)
	print returnval
	#now we need to update the individual events
	sys.exit(0)

if ((len(sys.argv)==3) and ("closealerts" in sys.argv[1])):
	print "Starting to close alerts"
	hec = PyHEC(AuthToken, "https://"+HOST)
	import splunklib.results as results
	import splunklib.client as client
	searchstring=sys.argv[2]
	print "About to connect to splunk - search is looking for "+searchstring
	# Create a Service instance and log in 
	service = client.connect(
    host=HOST,
    port=PORT,
    username=USERNAME,
    password=PASSWORD)

	kwargs_oneshot = {}
	searchquery_oneshot = "search index=itsi_grouped_alerts eventcorrelator=* device=* "+searchstring+"|`get_notable_event_state`|where event_id=itsi_first_event_id AND status < 5|dedup device,eventcorrelator|table event_id eventcorrelator device"

	oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)

	# Get the results and display them using the ResultsReader
	print "Starting Search"
	reader = results.ResultsReader(oneshotsearch_results)
	print "Search Completed"
	for item in reader:
		row = item.values()
		x = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(12))
		print("Closing EventId:"+row[0]+" for correlator:"+row[1]+ " on device:"+row[2]+" with new event:"+x)
		#"closeme\" : \"yes\", \"description\": \"AutoClose\"}}\'	
		event = {"event_id":x,"title":"AutoClose Maintenance","status":"3","severity":"1","eventcorrelator":row[1],"device":row[2],"owner":"unassigned","closeme":"yes","description":"AutoClose"}
		#myarray = item.split(",")
		print hec.send(event)
	sys.exit(0)
