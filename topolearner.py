from ryu.base import app_manager
import simple_switch_stp_13
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from ryu.lib import hub
import networkx as nx


class ProjectController(simple_switch_stp_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        # self.get_topology_data = hub.spawn(self.get_topology_data)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.datapaths = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i = 0
        self.monitor_thread = hub.spawn(self._monitor)
        self.fuck()
    
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)
        # use OFPFlowStatsRequest to get the Flow stats

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # def add_flow(self, datapath, priority, match, actions, buffer_id=None):
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser

    #     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
    #                                          actions)]
    #     if buffer_id:
    #         mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
    #                                 priority=priority, match=match,
    #                                 instructions=inst)
    #     else:
    #         mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
    #                                 match=match, instructions=inst)
    #     datapath.send_msg(mod)

    # def switch_features_handler(self, ev):
    #     datapath = ev.msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     match = parser.OFPMatch()
    #     actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
    #                                       ofproto.OFPCML_NO_BUFFER)]
    #     self.add_flow(datapath, 0, match, actions)

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def _packet_in_handler(self, ev):
    #     # If you hit this you might want to increase
    #     # the "miss_send_length" of your switch
    #     if ev.msg.msg_len < ev.msg.total_len:
    #         self.logger.debug("packet truncated: only %s of %s bytes",
    #                           ev.msg.msg_len, ev.msg.total_len)
    #     msg = ev.msg
    #     datapath = msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     in_port = msg.match['in_port']

    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocols(ethernet.ethernet)[0]

    #     if eth.ethertype == ether_types.ETH_TYPE_LLDP:
    #         # ignore lldp packet
    #         return
    #     dst = eth.dst
    #     src = eth.src

    #     dpid = format(datapath.id, "d").zfill(16)
    #     self.mac_to_port.setdefault(dpid, {})

    #     self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

    #     # learn a mac address to avoid FLOOD next time.
    #     self.mac_to_port[dpid][src] = in_port

    #     if dst in self.mac_to_port[dpid]:
    #         out_port = self.mac_to_port[dpid][dst]
    #     else:
    #         out_port = ofproto.OFPP_FLOOD

    #     actions = [parser.OFPActionOutput(out_port)]

    #     # install a flow to avoid packet_in next time
    #     if out_port != ofproto.OFPP_FLOOD:
    #         match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
    #         # verify if we have a valid buffer_id, if yes avoid to send both
    #         # flow_mod & packet_out
    #         if msg.buffer_id != ofproto.OFP_NO_BUFFER:
    #             self.add_flow(datapath, 1, match, actions, msg.buffer_id)
    #             return
    #         else:
    #             self.add_flow(datapath, 1, match, actions)
    #     data = None
    #     if msg.buffer_id == ofproto.OFP_NO_BUFFER:
    #         data = msg.data

    #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
    #                               in_port=in_port, actions=actions, data=data)
    #     datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        while True:
            switch_list = get_switch(self.topology_api_app, None)
            hub.sleep(1)
            switches = [switch.dp.id for switch in switch_list]
            self.net.add_nodes_from(switches)
            # print "**********List of switches"
            # for switch in switch_list:
            #     print switch
            links_list = get_link(self.topology_api_app, None)
            # print links_list
            links = [(link.src.dpid, link.dst.dpid, {
                      'port': link.src.port_no}) for link in links_list]
            # print links
            self.net.add_edges_from(links)

            links = [(link.dst.dpid, link.src.dpid, {
                      'port': link.dst.port_no}) for link in links_list]
            # print links
            self.net.add_edges_from(links)
            # print "**********List of links"
            # print self.net.edges()
            # hub.sleep(1)

    # @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    # def _port_stats_reply_handler(self, ev):
    #     body = ev.msg.body

    #     for stat in sorted(body, key=attrgetter('port_no')):
    #         if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
    #             key = (ev.msg.datapath.id, stat.port_no)
    #             value = (
    #                 stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
    #                 stat.duration_sec, stat.duration_nsec)

    #             self._save_stats(self.port_stats, key, value, self.state_len)

    #             # Get port speed.
    #             pre = 0
    #             period = self.sleep
    #             tmp = self.port_stats[key]
    #             if len(tmp) > 1:
    #                 pre = tmp[-2][0] + tmp[-2][1]
    #                 period = self._get_period(
    #                     tmp[-1][3], tmp[-1][4],
    #                     tmp[-2][3], tmp[-2][4])

    #             speed = self._get_speed(
    #                 self.port_stats[key][-1][0]+self.port_stats[key][-1][1],
    #                 pre, period)

    #             self._save_stats(self.port_speed, key, speed, self.state_len)
    #             print '\n Speed:\n', self.port_speed

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)