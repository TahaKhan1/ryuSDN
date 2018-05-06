#!/usr/bin/python

# from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

Nodes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
Links = [[1, 7], [1, 11], [1, 12], [2, 6], [2, 10], [3, 6], [3, 8], [3, 12], [4, 8], [4, 10],
         [5, 6], [5, 7], [5, 11], [6, 13], [7, 10], [9, 12], [9, 13], [10, 11], [4, 14], [14, 9], [14, 13]]


class NSFTopo(self):
    "Single switch connected to n hosts."

    def __init__(self, Nodes, Links):
        self.Nodes = Nodes
        self.Links = Links
        h = []
        for i in Nodes:
            host = 'h' + str(i)
            a = list(host)
            if len(a) > 2:
                j = a[1] + a[2]
                h.append(net.addHost(host, ip='10.0.0.%s' % j, mac='00:00:00:00:00:0%s' % j))
            else:
                j = a[1]
                h.append(net.addHost(host, ip='10.0.0.%s' % j, mac='00:00:00:00:00:0%s' % j))

        info('*** Adding switch\n')
        s = []
        for j in Nodes:
            switch = 's' + str(j)
            s.append(net.addSwitch(switch))
            """print(s)"""

        info('*** Creating links\n')
        ## One host at each switch
        for index in range(0, len(Nodes)):
            net.addLink(s[index], h[index])

        i = 0;
        for link_pair in Links:
            i = i + 1;
            net.addLink('s' + str(link_pair[0]), 's' + str(link_pair[1]))


def perfTest():
    "Create network and run simple performance test"
    topo = NSFTopo(Nodes, Links)
    net = Mininet(topo=topo, controller=RemoteController)
    net.start()

    "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print
    "Testing network connectivity"
    net.pingAll()
    print
    "Testing bandwidth between h1 and h4"
    h1, h4 = net.get('h1', 'h4')
    net.iperf((h1, h4))
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    perfTest()