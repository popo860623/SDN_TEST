from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink
from mininet.topo import Topo
import logging
import os

class CustomTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        self.s = []
        # for i in range(6):
        #     self.s.append(self.addSwitch(
        #         's' + str(i), protocols=OpenFlow13, mac=str(i)))

        self.s.append(self.addSwitch('S1', protocols='OpenFlow13'))
        self.s.append(self.addSwitch('S2', protocols='OpenFlow13'))
        self.s.append(self.addSwitch('U1', protocols='OpenFlow13'))
        self.s.append(self.addSwitch('V1', protocols='OpenFlow13'))
        self.s.append(self.addSwitch('D1', protocols='OpenFlow13'))
        self.s.append(self.addSwitch('D2', protocols='OpenFlow13'))

        self.addLink(self.s[0], self.s[4], bw=10, delay='100ms')
        self.addLink(self.s[0], self.s[2], bw=10, delay='100ms')
        self.addLink(self.s[1], self.s[2], bw=10, delay='100ms')
        self.addLink(self.s[1], self.s[5], bw=10, delay='100ms')
        self.addLink(self.s[2], self.s[3], bw=10, delay='100ms')
        self.addLink(self.s[3], self.s[4], bw=10, delay='100ms')
        self.addLink(self.s[3], self.s[5], bw=10, delay='100ms')
topos = {'mytopo': (lambda: CustomTopo())}


def createTopo():

    logging.debug("Create Topo")
    topo = CustomTopo()

    logging.debug("Start Mininet")

    CONTROLLER_IP = "127.0.0.1"
    CONTROLLER_PORT = 6633
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.addController(
        'controller', controller=RemoteController,
        ip=CONTROLLER_IP, port=CONTROLLER_PORT)
    # net.addController('controller',controller=Controller)
    net.start()

    # net.pingAll()
    CLI(net)
    net.stop()
if __name__ == '__main__':
    setLogLevel('info')
    createTopo()