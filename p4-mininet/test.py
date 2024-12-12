#!/usr/bin/env python
import multiprocessing

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
from p4_mininet import P4Switch, P4Host
from p4runtime_switch import P4RuntimeSwitch
sw_path = "simple_switch_grpc"
json_path = "build/demo.json"
def myNetwork():
    net = Mininet(topo=None,
                  build=False,
                  ipBase='10.0.0.0/8')
    net = Mininet(topo=None,
                  host=P4Host,
                  switch=P4RuntimeSwitch,
                  ipBase='10.0.0.0/8')



    info('*** Adding controller\n')
    c0 = net.addController(name='c0',
                           controller=RemoteController,
                           protocol='tcp',
                           port=6633)

    info('*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    # s2 = net.addSwitch('s2', cls=OVSKernelSwitch)

    s3 = net.addSwitch('s3',
              sw_path=sw_path,
              json_path=json_path,
              pcap_dump=False,cls=OVSKernelSwitch)

    info('*** Add hosts\n')

    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)

    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)


    info('*** Add links\n')

    net.addLink(s1, s3)
    net.addLink(s1, h1)
    net.addLink(s3, h2)
    net.addLink(h1,h2)
    #net.addLink(h2, h1)

    info('*** Starting network\n')
    net.build()
    info('*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info('*** Starting switches\n')
    net.get('s1').start([c0])

    #net.get('s2').start([c0])
    net.get('s3').start([c0])
    #h1.cmd("gnome-terminal -e 'bash -c \"h1 ping h2; exec bash\"'")

    #
    # info('*** Post configure switches and hosts\n')

    CLI(net)
    # net.stop()
    return net


if __name__ == '__main__':
    import os
    os.system('sudo mn -c')
    setLogLevel('info')
    net = myNetwork()

