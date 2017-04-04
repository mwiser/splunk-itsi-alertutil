# splunk-itsi-alertutil
This command line utility wraps around the splunk itsi rest endpoints (tested in 2.5.2) and performs modification activities like setting the status for events and event groups or setting/updating the severity. It can be leveraged in alert actions or external MoM integrations and event/alert synchronizations

usage: python alertutil.py closealerts "<query>"
usage: python alertutil.py setstatus "<eventid>" statusvalue
usage: python alertutil.py setseverity "<eventid>" severityvalue



