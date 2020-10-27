from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.node import RemoteController,OVSSwitch,UserSwitch
class MinimalTopo(Topo):
    def build(self):	
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )
        self.addLink( s1, s2 )
        self.addLink( s2, s3 )
        self.addLink( s3, s1 )
        self.addLink( s3, h3 )
        self.addLink( s2, h2 )
        self.addLink( s1, h1 )
def runMinimalTopo():
	topo = MinimalTopo()
	net = Mininet(topo=topo,controller=lambda nampe: RemoteController(name, ip='127.0.0.1'),switch=UserSwitch,autoSetMacs=True)
	net.start()
	CLI(net)
	net.stop()
if __name__ == '__main__':
	setLogLevel('info')
	runMinimalTopo()
topos = {'topo':MinimalTopo}