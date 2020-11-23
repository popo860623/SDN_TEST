from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import in_proto
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.lib import hub
from ryu.lib import ip
from ryu.topology.api import get_switch, get_link, get_all_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event
from ryu.app import simple_switch_stp_13
from collections import defaultdict
from operator import itemgetter, attrgetter

import os
import copy
import sys
import numpy as np
import random
import time

REFERENCE_BW = 10000000
class MyMonitor(simple_switch_stp_13.SimpleSwitch13):    #simple_switch_13 is same as the last experiment which named self_learn_switch
    '''
    design a class to achvie managing the quantity of flow
    '''

    def __init__(self,*args,**kwargs):
        super(MyMonitor,self).__init__(*args,**kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.delay_matrix = []
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: 10000000))
        # Bandwidth Monitor
        self.switch_port_to_switch = []
        self.linkbw_matrix = []
        self.tmp_linkbw_matrix = []
        self.linkbw_matrix_old = []
        self.rbw_matrix = []
        self.monitor_thread = hub.spawn(self._bw_monitor)

    def _bw_monitor(self):
        while True:
            for dp in self.datapath_list.values():
                # print 'dp = ' + str(dp)
                self._request_stats(dp)

            self.get_switch_port_to_switch_mapping()
            self.get_linkbw_matrix()

            hub.sleep(2)

    

    def get_switch_port_to_switch_mapping(self):
        for link in get_all_link(self):
            if link.src.port_no != 4294967294:
                # print 'link.src.dpid = ' + str(link.src.dpid) + ',link.src.port = ' + str(link.src.port_no) + 'link.dst.dpid = ' + str(link.dst.dpid)
                self.switch_port_to_switch[link.src.dpid][link.src.port_no] = link.dst.dpid
                self.switch_port_to_switch[link.dst.dpid][link.dst.port_no] = link.src.dpid

    def get_linkbw_matrix(self):
        len1 = len(self.linkbw_matrix)
        self.rbw_matrix = np.full((len1,len1),REFERENCE_BW)
        self.linkbw_matrix_old = np.copy(self.linkbw_matrix)
        self.linkbw_matrix = np.copy(self.tmp_linkbw_matrix)
        LINKBW_MATRIX = self.linkbw_matrix - self.linkbw_matrix_old
        print 'LINKBW_MATRIX = \n' + str(LINKBW_MATRIX)
        self.rbw_matrix = self.rbw_matrix - LINKBW_MATRIX

    def _request_stats(self,datapath):
        '''
        the function is to send requery to datapath
        '''
        self.logger.debug("send stats reques to datapath: %16x for port and flow info",datapath.id)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPPortStatsReply,MAIN_DISPATCHER)
    def _port_stats_reply_handler(self,ev):
        switch = ev.msg.datapath
        body = ev.msg.body
        
        for stat in sorted(body,key=attrgetter('port_no')):
                if stat.port_no != 4294967294 and self.switch_port_to_switch[switch.id][stat.port_no] != 0:
                    self.tmp_linkbw_matrix[switch.id][self.switch_port_to_switch[switch.id]
                                                  [stat.port_no]] = stat.tx_bytes


    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        switch = event.switch.dp
        ofp_parser = switch.ofproto_parser
        
        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch
            print self.switches

            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

        # For Bandwidth Monitor Init
        self.switch_port_to_switch = [[0 for row in range(
            len(self.switches)+1)] for col in range(len(self.switches)+1)]

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, event):
        print event
        switch = event.switch.dp.id
        if switch in self.switches:
            del self.switches[switch]
            del self.datapath_list[switch]
            del self.adjacency[switch]

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, event):
        s1 = event.link.src
        s2 = event.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, event):
        return