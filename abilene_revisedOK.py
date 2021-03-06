#!/usr/bin/python

"""
Custom topology for Mininet, generated by GraphML-Topo-to-Mininet-Network-Generator.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import Node,OVSKernelSwitch
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel,info

class GeneratedTopo( Topo ):
    "Internet Topology Zoo Specimen."

    def __init__( self, **opts ):
        "Create a topology."

        # Initialize Topology
        Topo.__init__( self, **opts )

        # add nodes
        # switches first
        NewYork = self.addSwitch( 's1' , cls=OVSKernelSwitch)
        Chicago = self.addSwitch( 's2' , cls=OVSKernelSwitch)
        WashingtonDC = self.addSwitch( 's3' , cls=OVSKernelSwitch)
        Seattle = self.addSwitch( 's4' , cls=OVSKernelSwitch)
        Sunnyvale = self.addSwitch( 's5' , cls=OVSKernelSwitch)
        LosAngeles = self.addSwitch( 's6' , cls=OVSKernelSwitch)
        Denver = self.addSwitch( 's7' , cls=OVSKernelSwitch)
        KansasCity = self.addSwitch( 's8' , cls=OVSKernelSwitch)
        Houston = self.addSwitch( 's9' , cls=OVSKernelSwitch)
        Atlanta = self.addSwitch( 's10' , cls=OVSKernelSwitch)
        Indianapolis = self.addSwitch( 's11' , cls=OVSKernelSwitch)

        # and now hosts
        NewYork_host = self.addHost( 'h0' )
        Chicago_host = self.addHost( 'h1' )
        WashingtonDC_host = self.addHost( 'h2' )
        Seattle_host = self.addHost( 'h3' )
        Sunnyvale_host = self.addHost( 'h4' )
        LosAngeles_host = self.addHost( 'h5' )
        Denver_host = self.addHost( 'h6' )
        KansasCity_host = self.addHost( 'h7' )
        Houston_host = self.addHost( 'h8' )
        Atlanta_host = self.addHost( 'h9' )
        Indianapolis_host = self.addHost( 'h10' )

        # add edges between switch and corresponding host
        self.addLink( NewYork , NewYork_host )
        self.addLink( Chicago , Chicago_host )
        self.addLink( WashingtonDC , WashingtonDC_host )
        self.addLink( Seattle , Seattle_host )
        self.addLink( Sunnyvale , Sunnyvale_host )
        self.addLink( LosAngeles , LosAngeles_host )
        self.addLink( Denver , Denver_host )
        self.addLink( KansasCity , KansasCity_host )
        self.addLink( Houston , Houston_host )
        self.addLink( Atlanta , Atlanta_host )
        self.addLink( Indianapolis , Indianapolis_host )
        # add edges between switches
        self.addLink( NewYork , Chicago, bw=10, delay='0.690677696537ms')
        self.addLink( NewYork , WashingtonDC, bw=10, delay='0.518903303662ms')
        self.addLink( Chicago , Indianapolis, bw=10, delay='1.15170240387ms')
        self.addLink( WashingtonDC , Atlanta, bw=10, delay='0.477628158502ms')
        self.addLink( Seattle , Sunnyvale, bw=10, delay='1.10351797289ms')
        self.addLink( Seattle , Denver, bw=10, delay='0.952189623151ms')
        self.addLink( Sunnyvale , LosAngeles, bw=10, delay='0.506044716762ms')
        self.addLink( Sunnyvale , Denver, bw=10, delay='0.85423284091ms')
        self.addLink( LosAngeles , Houston, bw=10, delay='1.02920365882ms')
        self.addLink( Denver , KansasCity, bw=10, delay='0.191285963954ms')
        self.addLink( KansasCity , Houston, bw=10, delay='1.46743666378ms')
        self.addLink( KansasCity , Indianapolis, bw=10, delay='0.206336052247ms')
        self.addLink( Houston , Atlanta, bw=10, delay='1.15068985002ms')
        self.addLink( Atlanta , Indianapolis, bw=10, delay='0.466772343871ms')

topos = { 'generated': ( lambda: GeneratedTopo() ) }

# here the code defining the topology ends
# the following code produces an executable script working with a remote controller
# and ssh access to the the mininet hosts from within the ubuntu vm
def setupNetwork():
    "Create network and run simple performance test"
    topo = GeneratedTopo()
    net = Mininet(topo=topo, controller=lambda a: RemoteController( a, ip='127.0.0.1', port=6633 ), host=CPULimitedHost, link=TCLink)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')

    setupNetwork()
