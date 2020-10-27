from ryu.app import simple_switch_stp_13
from ryu.base import app_manager
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
from ryu.topology.api import get_switch, get_all_switch, get_link, get_all_link, get_host, get_all_host
from ryu.lib import hub
import networkx as nx

class Test(simple_switch_stp_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(Test, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.topology_thread = hub.spawn(self._topology_thread)
        self.links = []

    def _topology_thread(self):
        while True:
            print '***********************'
            switches = get_all_switch(self)
            print 'All Switch = '
            print switches
            links = get_all_link(self)
            print 'All Links = '
            print links
            # print links
            hub.sleep(1)


    