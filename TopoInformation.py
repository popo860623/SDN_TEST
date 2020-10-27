DB_servicePort_serverIP_clientIP=[]
forwardingTable = {}
distanceTable = {}
TopoNumberTo = []
all_host=[]
ip_mac={}
all_switch=[]
all_link=[]
datapaths = {}
ArpTable={}
flow_stats={}
SwitchFlowLoading={}

ready=False

#there is a bug when tuple is one-to-many with muliple-servicePort
def add_DB_servicePort_serverIP_clientIP(servicePort,MainserverIP,NewserverIP,clientIP):
	global DB_servicePort_serverIP_clientIP
	for i in DB_servicePort_serverIP_clientIP:
		if i['servicePort'] == servicePort and i['MainserverIP'] == MainserverIP and i['NewserverIP'] == NewserverIP and i['clientIP'] == clientIP:
			return 'exist'
	tup={}
	tup['servicePort']=servicePort
	tup['MainserverIP']=MainserverIP
	tup['NewserverIP']=NewserverIP
	tup['clientIP']=clientIP
	DB_servicePort_serverIP_clientIP.append(tup)
	return 'success'
def del_DB_servicePort_serverIP_clientIP(servicePort,MainserverIP,NewserverIP,clientIP):
	global DB_servicePort_serverIP_clientIP

	for i in range(0,len(DB_servicePort_serverIP_clientIP)) :
		if DB_servicePort_serverIP_clientIP[i]['servicePort'] == servicePort and DB_servicePort_serverIP_clientIP[i]['MainserverIP'] == MainserverIP and DB_servicePort_serverIP_clientIP[i]['NewserverIP'] == NewserverIP and DB_servicePort_serverIP_clientIP[i]['clientIP'] == clientIP:
			DB_servicePort_serverIP_clientIP.pop(i)
			return 'success'
	return 'notexist'

def get_SwitchFlowLoading(dpid):
	global SwitchFlowLoading
	if dpid not in SwitchFlowLoading:
		return []
	return [flow for flow in SwitchFlowLoading[dpid] if (flow['now']-flow['old'] > 0 and flow['ip_proto']==17)]
def set_SwitchFlowLoading(dpid,body):
	global SwitchFlowLoading
	if dpid not in SwitchFlowLoading:
		SwitchFlowLoading[dpid]=[]
	#print 'len = '+str(len([flow for flow in body if flow.priority == 4096]))
	for stat in [flow for flow in body if (flow.priority == 4096 or flow.priority == 4097)]:
		exist=False
		for item in SwitchFlowLoading[dpid] :
			if item['priority'] == stat.priority and item['ip_proto'] == stat.match['ip_proto'] and item['src'] == stat.match['ipv4_src'] and item['dst'] == stat.match['ipv4_dst']:
				exist=True
				item['old']=item['now']
				item['now']=stat.packet_count
		if exist==False :
			SwitchFlowLoading[dpid].append({'priority':stat.priority,'ip_proto':stat.match['ip_proto'],'src':stat.match['ipv4_src'],'dst':stat.match['ipv4_dst'],'now':stat.packet_count,'old':0})
	return SwitchFlowLoading
	
def get_DB_servicePort_serverIP_clientIP():
	global DB_servicePort_serverIP_clientIP
	return DB_servicePort_serverIP_clientIP

def get_forwardingTable():
	global forwardingTable
	return forwardingTable

def get_distanceTable():
	global distanceTable
	return distanceTable

def get_TopoNumberTo():
	global TopoNumberTo
	return TopoNumberTo

def Get_all_host():
	global all_host
	return all_host
def Set_all_host(all_hosts):
	global all_host
	all_host=all_hosts
	return

def Get_all_switch():
	global all_switch
	return all_switch
def Set_all_switch(switchs):
	global all_switch
	all_switch=switchs
	return

def Get_all_link():
	global all_link
	return all_link
def Set_all_link(links):
	global all_link
	all_link=links
	return

def Get_ip_mac():
	global ip_mac
	return ip_mac

def Get_datapaths():
	global datapaths
	return datapaths

def Get_ArpTable():
	global ArpTable
	return ArpTable

def Get_flow_stats():
	global flow_stats
	return flow_stats



def Get_ready():
	global ready
	return ready
def Set_ready(r):
	global ready
	ready=r
	return

