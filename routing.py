from operator import attrgetter
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
import thread
import requests
import urllib2
import sys
import copy
import math
import json
from TopoInformation import *
import time
def addrouting(servicePort,MainserverIP,NewserverIP,clientIP):


	while Get_ready() == False:
		print Get_ready()
	if clientIP not in Get_ip_mac() or MainserverIP not in Get_ip_mac() or NewserverIP not in Get_ip_mac():
		return False
	mac_client=Get_ip_mac()[clientIP]
	mac_Oldserver=Get_ip_mac()[MainserverIP]
	mac_Newserver=Get_ip_mac()[NewserverIP]
	dpid = -1
	for host in Get_all_host():
		if host.mac == mac_client:
			dpid = host.port.dpid
	datapath =Get_datapaths()[dpid]
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
	print '****** set rule *******'

	matchTo = parser.OFPMatch(eth_src = mac_client , eth_dst=mac_Oldserver , eth_type = 0x0800 , ip_proto = 17 , ipv4_src = clientIP , ipv4_dst = MainserverIP , udp_dst = servicePort)
	out_portTo = get_forwardingTable()[dpid][mac_Newserver]
	actionsTo = [parser.OFPActionSetField(eth_dst=mac_Newserver),
		parser.OFPActionSetField(ipv4_dst = NewserverIP),
		parser.OFPActionOutput(out_portTo)]
	instTo = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actionsTo)]
	modTo = parser.OFPFlowMod(datapath=datapath, priority=4097, match=matchTo, instructions=instTo)
	datapath.send_msg(modTo)

	

	matchBack = parser.OFPMatch(eth_src = mac_Newserver , eth_dst=mac_client , eth_type = 0x0800 , ip_proto = 17 , ipv4_src = NewserverIP , ipv4_dst = clientIP , udp_src = servicePort )
	out_portBack = get_forwardingTable()[dpid][mac_client]
	actionsBack = [parser.OFPActionSetField(eth_src=mac_Oldserver),
		parser.OFPActionSetField(ipv4_src = MainserverIP),
		parser.OFPActionOutput(out_portBack)]
	instBack = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actionsBack)]
	modBack = parser.OFPFlowMod(datapath=datapath, priority=4097, match=matchBack, instructions=instBack)
	datapath.send_msg(modBack)

	return True

def delrouting(servicePort,MainserverIP,NewserverIP,clientIP):

	while Get_ready() == False:
		print Get_ready()
	if clientIP not in Get_ip_mac() :
		return False
	if MainserverIP not in Get_ip_mac():
		return False
	if NewserverIP not in Get_ip_mac():
		return False
	mac_client=Get_ip_mac()[clientIP]
	mac_Oldserver=Get_ip_mac()[MainserverIP]
	mac_Newserver=Get_ip_mac()[NewserverIP]
	dpid = -1
	for host in Get_all_host():
		if host.mac == mac_client:
			dpid = host.port.dpid
	datapath =Get_datapaths()[dpid]
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
	print '****** del rule *******'
	matchTo = parser.OFPMatch(eth_src = mac_client , eth_dst=mac_Oldserver , eth_type = 0x0800 , ip_proto = 17 , ipv4_src = clientIP , ipv4_dst = MainserverIP , udp_dst = servicePort)
	out_portTo = get_forwardingTable()[dpid][mac_Newserver]
	actionsTo = [parser.OFPActionSetField(eth_dst=mac_Newserver),
		parser.OFPActionSetField(ipv4_dst = NewserverIP),
		parser.OFPActionOutput(out_portTo)]
	instTo = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actionsTo)]
	modTo = parser.OFPFlowMod(datapath=datapath, priority=4097, match=matchTo, instructions=instTo, command=datapath.ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
	datapath.send_msg(modTo)


	matchBack = parser.OFPMatch(eth_src = mac_Newserver , eth_dst=mac_client , eth_type = 0x0800 , ip_proto = 17 , ipv4_src = NewserverIP , ipv4_dst = clientIP , udp_src = servicePort )
	out_portBack = get_forwardingTable()[dpid][mac_client]
	actionsBack = [parser.OFPActionSetField(eth_src=mac_Oldserver),
		parser.OFPActionSetField(ipv4_src = MainserverIP),
		parser.OFPActionOutput(out_portBack)]
	instBack = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actionsBack)]
	modBack = parser.OFPFlowMod(datapath=datapath, priority=4097, match=matchBack, instructions=instBack, command=datapath.ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
	datapath.send_msg(modBack)
	return True

