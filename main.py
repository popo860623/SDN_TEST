from operator import attrgetter

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_all_switch, get_link, get_all_link, get_host, get_all_host
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
import thread
import requests
import urllib2
import sys
import copy
import math
import json
from pandas import *
import numpy as np
from ForwardingTableModule import *
from restmodule import *


class ProjectMainController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectMainController, self).__init__(*args, **kwargs)
        self.topology_thread = hub.spawn(self._topology_thread)
        self.monitor_thread = hub.spawn(self._monitor)
        self.each_switch_EC = {}
        self.datapaths = {}
        self.port = {}
        self.switch = {}
        self.bw_matrix = {}
        self.switch_port_to_switch = []
        self.link_bw = []
        print 'adsfasdfasdfas'

        for i in range(1, 11):
            self.each_switch_EC[i] = []

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # self.logger.info("****** Add DefualtFlow *******")
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[str(datapath.id)] = datapath
        tmp = {}
        msg = ev.msg
        tmp["datapath_id"] = msg.datapath_id
        tmp["n_buffers"] = msg.n_buffers
        tmp["n_tables"] = msg.n_tables
        tmp["auxiliary_id"] = msg.auxiliary_id
        tmp["capabilities"] = msg.capabilities
        self.switch[str(datapath.id)] = tmp

        # print '**************Switches**********************'
        # print 'switch[' + str(datapath.id) + '] = \n' + str(tmp)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        # add table-miss flow to switch
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        print '********Port Status***************'
        self.port[str(ev.msg.datapath.id)] = {}
        for p in ev.msg.body:
            tmp = {}
            tmp["port_no"] = p.port_no
            tmp["hw_addr"] = p.hw_addr
            tmp["name"] = p.name
            tmp["config"] = p.config
            tmp["state"] = p.state
            tmp["curr"] = p.curr
            tmp["advertised"] = p.advertised
            tmp["supported"] = p.supported
            tmp["peer"] = p.peer
            tmp["curr_speed"] = p.curr_speed
            tmp["max_speed"] = p.max_speed
            self.port[str(ev.msg.datapath.id)][str(p.port_no)] = tmp
            print 'port[' + str(ev.msg.datapath.id) + '][' + \
                str(p.port_no) + '] = \n' + str(tmp)
            if p.port_no != 4294967294:
                self.link_bw[ev.msg.datapath.id][p.port_no] = p.curr_speed

    def _monitor(self):
        while True:
            for dp in Get_datapaths().values():
                self._request_flow_stats(dp)
                self.send_port_desc_stats_request(dp)

            print 'link_bw = \n' + str(np.matrix(self.link_bw))

            hub.sleep(2)
        # use OFPFlowStatsRequest to get the Flow stats

    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def _request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # receive the OFPFlowStatsRequest's reply

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        set_SwitchFlowLoading(dpid, body)
        Get_flow_stats()[dpid] = json.dumps(
            ev.msg.to_jsondict(), ensure_ascii=True, indent=3, sort_keys=True)
        # print str(Get_flow_stats()[dpid])
        # print 'SwitchFlowLoading = '+str(get_SwitchFlowLoading(dpid))
        # return # of rules on switches
        # print 'switch[ ' + str(dpid)+' ] = ' + str(len(get_SwitchFlowLoading(dpid)))
        self.each_switch_EC[dpid].append(len(get_SwitchFlowLoading(dpid)))
        ret = json.dumps(self.each_switch_EC)
        with open("ECFatTree2.txt", "w") as f:
            f.write(ret)
            f.close()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # print 'packet_in'
        DB = get_DB_servicePort_serverIP_clientIP()
        # print DB
        if Get_ready() == False:
            return

        msg = ev.msg
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        # print 'protocol = ' + str(pkt.get_protocol(arp.arp))
        # print msg.data
        if pkt_ethernet.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        pkt_arp = pkt.get_protocol(arp.arp)
        # Select received Packet and judge which packet it is
        # if arp protocols exists,it will return non-Null value
        if pkt_arp:
            self._handle_arp(msg=msg, pkt=pkt)
            return
        else:
            self._handle_packet(msg=msg, pkt=pkt)
            return

    def _handle_arp(self, msg, pkt):
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        for ToPort in Get_ArpTable()[dpid]:
            if ToPort != in_port:
                actions = [parser.OFPActionOutput(port=ToPort)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=msg.buffer_id,
                                          in_port=in_port,
                                          actions=actions,
                                          data=data)
                datapath.send_msg(out)

    def _handle_packet(self, msg, pkt):
        in_port = msg.match['in_port']
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data = None
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        dst = pkt_ethernet.dst
        src = pkt_ethernet.src
        if dst in get_forwardingTable()[dpid]:
            pktip = pkt.get_protocol(ipv4.ipv4)
            pkticmp = pkt.get_protocol(icmp.icmp)
            pkttcp = pkt.get_protocol(tcp.tcp)
            pktudp = pkt.get_protocol(udp.udp)
            Get_ip_mac()[pktip.dst] = dst
            Get_ip_mac()[pktip.src] = src
            # print 'ip_mac = ' + str(Get_ip_mac())
            # self.logger.info("****** set flow *******")
            if pktip:
                if pkticmp:
                    print '*****ICMP*****'
                    match = parser.OFPMatch(
                        eth_src=src, eth_dst=dst, eth_type=0x0800, ipv4_src=pktip.src, ipv4_dst=pktip.dst, ip_proto=1)
                elif pkttcp:
                    print '*****TCP*****'
                    match = parser.OFPMatch(eth_src=src, eth_dst=dst, eth_type=0x0800,
                                            ipv4_src=pktip.src, ipv4_dst=pktip.dst, ip_proto=6, tcp_dst=pkttcp.dst_port)
                elif pktudp:
                    print '*****UDP***** '+str(pktip.src)+' to '+str(pktip.dst)
                    match = parser.OFPMatch(eth_src=src, eth_dst=dst, eth_type=0x0800,
                                            ipv4_src=pktip.src, ipv4_dst=pktip.dst, ip_proto=17, udp_dst=pktudp.dst_port)
                else:
                    print '*****Others*****'
                    match = parser.OFPMatch(eth_src=src, eth_dst=dst, eth_type=0x0800,
                                            ipv4_src=pktip.src, ipv4_dst=pktip.dst, ip_proto=pktip.proto)
        # Switch not recognize the flow so add flow rule to Switch
            else:
                match = parser.OFPMatch(
                    eth_src=eth.src, eth_dst=eth.dst, eth_type=pkt_ethernet.ethertype)
            out_port = get_forwardingTable()[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=4096, match=match, instructions=inst)
            datapath.send_msg(mod)
            # self.logger.info("****** Packet In *******")
            actions = [parser.OFPActionOutput(port=out_port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=data)
            # self.logger.info("****** send *******")
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in Get_datapaths():
                self.logger.debug('register datapath: %016x', datapath.id)
                Get_datapaths()[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in Get_datapaths():
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del Get_datapaths()[datapath.id]

    def _topology_thread(self):
        while True:
            all_switch = get_all_switch(self)
            Set_all_switch(all_switch)
            all_link = get_all_link(self)
            Set_all_link(all_link)
            all_host = get_all_host(self)
            Set_all_host(all_host)
            self.link_bw = [[0 for row in range(len(Get_all_switch())+1)] for col in range(len(Get_all_switch())+1)]
            print 'All Switch = ' + str(len(Get_all_switch()))
            print 'All Link = ' + str(len(Get_all_link()))
            print 'All Host = ' + str(len(Get_all_host()))

            # for a in Get_all_host():
            #     print a.ipv4
            hub.sleep(1)
            if len(Get_all_switch()) == 6:
                for i in range(0, len(Get_all_switch())):
                    get_TopoNumberTo().append(['switch', all_switch[i]])

                for i in range(0, len(Get_all_switch()) + 1):
                    self.switch_port_to_switch.append(
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

                for i in range(0, len(Get_all_host())):
                    get_TopoNumberTo().append(['host', all_host[i]])

                # print 'get_TopoNumberTo = ' + str(get_TopoNumberTo())
                connectMatrix = []
                for i in range(0, len(get_TopoNumberTo())):
                    connectMatrix.append([999999999]*len(get_TopoNumberTo()))
                for i in range(0, len(connectMatrix)):
                    for j in range(0, len(connectMatrix[i])):
                        if i == j:
                            connectMatrix[i][j] = 0


                # Find each link's src & dst
                # Controller get all switch_port_to_switch
                for link in Get_all_link():
                    print 'link = ' + str(link)
                    indexA = 0
                    indexB = 0
                    for i in get_TopoNumberTo():
                        if i[0] == 'switch' and i[1].dp.id == link.src.dpid:
                            indexA = get_TopoNumberTo().index(i)

                        if i[0] == 'switch' and i[1].dp.id == link.dst.dpid:
                            indexB = get_TopoNumberTo().index(i)

                        if link.src.port_no != 4294967294:
                            self.switch_port_to_switch[link.src.dpid][link.src.port_no] = link.dst.dpid
                            self.switch_port_to_switch[link.dst.dpid][link.dst.port_no] = link.src.dpid

                    # connectMatrix[src][dst] = 1 represent A to B is connected
                    connectMatrix[indexA][indexB] = 1
                    connectMatrix[indexB][indexA] = 1
                # print 'Switch Port to Switch = \n' + \
                #     str(np.matrix(self.switch_port_to_switch))
                # Controller get (host,switch) connection
                for host in Get_all_host():
                    indexA = 0
                    indexB = 0
                    for i in get_TopoNumberTo():
                        if i[0] == 'host' and i[1] == host:
                            # src
                            indexA = get_TopoNumberTo().index(i)
                        # check whether there is a link exists between host and switch
                        if i[0] == 'switch' and i[1].dp.id == host.port.dpid:
                            # dst
                            indexB = get_TopoNumberTo().index(i)
                    connectMatrix[indexA][indexB] = 1
                    connectMatrix[indexB][indexA] = 1
                print 'connectMatrix = '
                print np.matrix(connectMatrix)
                # forwarding matrix to forwarding Table
                forwardingMatrix, distance = MakeForwardingTable(connectMatrix)
                print 'forwardingMatrix :\n' + str(np.matrix(forwardingMatrix))
                print 'distance : \n' + str(distance)
                for i in range(0, len(get_TopoNumberTo())):
                    if get_TopoNumberTo()[i][0] == 'switch':
                        switchdp = get_TopoNumberTo()[i][1].dp.id
                        # Create Switch's forwardingTable : {'dpid':{}}
                        get_forwardingTable()[switchdp] = {}
                        for j in range(0, len(forwardingMatrix[i])):
                            if get_TopoNumberTo()[j][0] == 'host':
                                dsthost = get_TopoNumberTo()[j][1].mac
                                Pport = -1
                                if get_TopoNumberTo()[forwardingMatrix[i][j]][0] == 'switch':
                                    for link in Get_all_link():
                                        if link.src.dpid == switchdp and link.dst.dpid == get_TopoNumberTo()[forwardingMatrix[i][j]][1].dp.id:
                                            Pport = link.src.port_no
                                if get_TopoNumberTo()[forwardingMatrix[i][j]][0] == 'host':
                                    Pport = get_TopoNumberTo()[
                                        j][1].port.port_no
                                if Pport == -1:
                                    print 'host not found'
                                    return
                                else:
                                    get_forwardingTable()[
                                        switchdp][dsthost] = Pport
                print 'get_forwardingTable'
                print get_forwardingTable()
                for i in range(0, len(distance)):
                    if get_TopoNumberTo()[i][0] == 'host':
                        get_distanceTable()[get_TopoNumberTo()[i][1].mac] = {}
                        for j in range(0, len(distance[i])):
                            if get_TopoNumberTo()[j][0] == 'host':
                                get_distanceTable()[get_TopoNumberTo()[i][1].mac][get_TopoNumberTo()[
                                    j][1].mac] = distance[i][j]
                print get_distanceTable()

                # arpMatrix to ArpTable
                check = [0]*len(get_TopoNumberTo())
                check[0] = 1
                arpMatrix = []
                for i in range(0, len(get_TopoNumberTo())):
                    arpMatrix.append([0]*len(get_TopoNumberTo()))
                SPTqueue = []
                SPTqueue.append(0)
                while len(SPTqueue) != 0:
                    i = SPTqueue.pop(0)
                    for j in range(0, len(get_TopoNumberTo())):
                        if connectMatrix[i][j] == 1 and check[j] == 0:
                            arpMatrix[i][j] = 1
                            arpMatrix[j][i] = 1
                            check[j] = 1
                            SPTqueue.append(j)

                print "get_TopoNumberTo() = "
                for i in get_TopoNumberTo():
                    print '['+str(i)+'] = '+str(get_TopoNumberTo()[0])
                print "arpMatrix = "
                print arpMatrix
                for i in range(0, len(get_TopoNumberTo())):
                    if get_TopoNumberTo()[i][0] == 'switch':
                        switchdp = get_TopoNumberTo()[i][1].dp.id
                        Get_ArpTable()[switchdp] = []
                        for j in range(0, len(arpMatrix[i])):
                            if arpMatrix[i][j] == 1:
                                Pport = -1
                                if get_TopoNumberTo()[j][0] == 'switch':
                                    for link in Get_all_link():
                                        if link.src.dpid == switchdp and link.dst.dpid == get_TopoNumberTo()[j][1].dp.id:
                                            Pport = link.src.port_no
                                if get_TopoNumberTo()[j][0] == 'host':
                                    Pport = get_TopoNumberTo()[
                                        j][1].port.port_no
                                if Pport == -1:
                                    print 'Pport not found'
                                    return
                                else:
                                    Get_ArpTable()[switchdp].append(Pport)
                print "ARP Table = "
                print Get_ArpTable()
                Set_ready(True)
                break
