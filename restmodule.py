from flask import Flask, url_for
from flask import request
from flask import Response

import json
import thread
from routing import *
from TopoInformation import *
app = Flask(__name__)

def flaskThread():
	app.run()

@app.route('/')
def api_root():
	return 'Welcome\n'

@app.route('/get_flow_state', methods=['POST'])
def api_get_flow_state():
	data = request.get_data()
	jsondata = json.loads(data)
	hostip = jsondata['hostip']
	
	if len(Get_ip_mac().items()) == 0:
		return json.dumps({})
	if hostip not in Get_ip_mac():
		return json.dumps({})
	hostmac=Get_ip_mac()[hostip]
	dpid=-1
	
	for h in Get_all_host():
		if h.mac == hostmac:
			dpid = h.port.dpid
	if dpid == -1:
		return 'not exit'

	else:
		if dpid in Get_flow_stats():
			return Get_flow_stats()[dpid]
		else:
			return json.dumps({})
	

@app.route('/distance', methods=['GET'])
def api_get_distance():
	inv_ip_mac = {v: k for k, v in Get_ip_mac().items()}
	IPdistanceTable={}
	if inv_ip_mac=={}:
		return json.dumps(IPdistanceTable)
	#return json.dumps({})
	#print 'inv_ip_mac = '+str(inv_ip_mac)
	#print 'get_distanceTable() = '+str(get_distanceTable())
	for macsrc in get_distanceTable():
		if macsrc not in inv_ip_mac:
			return json.dumps({})
		IPdistanceTable[inv_ip_mac[macsrc]]={}
		for macdst in get_distanceTable()[macsrc]:
			if macdst not in inv_ip_mac:
				return json.dumps({})
			IPdistanceTable[inv_ip_mac[macsrc]][inv_ip_mac[macdst]]=get_distanceTable()[macsrc][macdst]


	return json.dumps(IPdistanceTable)


@app.route('/alltuple', methods=['GET'])
def api_getdata():
	DB=get_DB_servicePort_serverIP_clientIP()
	
	data = json.dumps(DB)
	return data

@app.route('/set', methods=['POST'])
def api_setdata():
	data = request.get_data()
	jsondata = json.loads(data)
	servicePort = jsondata['servicePort']
	MainserverIP = jsondata['MainserverIP']
	NewserverIP = jsondata['NewserverIP']
	clientIP = jsondata['clientIP']
	ms = add_DB_servicePort_serverIP_clientIP(servicePort=servicePort,MainserverIP=MainserverIP,NewserverIP=NewserverIP,clientIP=clientIP)
	print 'set ******'+ms+'*******'
	if ms == 'exist':
		return 'Rule is already exist'
	elif ms == 'success' :
		ss=addrouting(servicePort,MainserverIP,NewserverIP,clientIP)
		if ss == False:
			return 'IP is not exist'
		return 'set success'
	return 'error'

@app.route('/del', methods=['POST'])
def api_deldata():
	data = request.get_data()
	jsondata = json.loads(data)
	servicePort = jsondata[u'servicePort']
	MainserverIP = jsondata[u'MainserverIP']
	NewserverIP = jsondata[u'NewserverIP']
	clientIP = jsondata[u'clientIP']
	ms = del_DB_servicePort_serverIP_clientIP(servicePort=servicePort,MainserverIP=MainserverIP,NewserverIP=NewserverIP,clientIP=clientIP)
	print 'del ******'+ms+'*******'
	if ms =='success':
		ss = delrouting(servicePort,MainserverIP,NewserverIP,clientIP)
		if ss == True:
			return 'success'
		else :
			return 'error 1'
	elif ms=='notexist':
		return 'rule not exist'
	return 'error 2'


