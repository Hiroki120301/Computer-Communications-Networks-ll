from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib import mac

import json
import random

class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)

        # Load the configuration file
        with open('lb_config.json') as f:
            self.config = json.load(f)
        
        # Initialize the server pools for red and blue services
        self.red_servers = self.config['red_servers']
        self.blue_servers = self.config['blue_servers']
        
        # Load balancer MAC and IP for red and blue services
        self.red_service_ip = self.config['red_service_ip']
        self.blue_service_ip = self.config['blue_service_ip']
        self.service_mac = self.config['service_mac']

        # Server selection counters for round-robin
        self.red_index = 0
        self.blue_index = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """ Handle switch feature event to install table-miss flow entry """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Request MAC addresses of all servers
        self.request_server_macs(datapath)

    def request_server_macs(self, datapath):
        """ Preemptively send ARP requests to get the MAC addresses of the servers """
        for server in self.red_servers + self.blue_servers:
            self.send_arp_request(datapath, server['ip'], self.service_mac)

    def send_arp_request(self, datapath, ip, src_mac):
        """ Send an ARP request to get the MAC address for a given IP """
        pkt = packet.Packet()
        ether = ethernet.ethernet(dst=mac.BROADCAST_STR, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
        arp_req = arp.arp(opcode=arp.ARP_REQUEST, src_mac=src_mac, src_ip=self.red_service_ip, dst_mac=mac.DONTCARE_STR, dst_ip=ip)
        pkt.add_protocol(ether)
        pkt.add_protocol(arp_req)
        pkt.serialize()

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=10):
        """ Add a flow rule to the switch """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """ Handle incoming packets (mainly ARP and IPv4) """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Handle ARP requests
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, pkt, eth, in_port)
            return

        # Handle IPv4 packets for load balancing
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.handle_ipv4(datapath, pkt, eth, ip_pkt, in_port)

    def handle_arp(self, datapath, pkt, eth, in_port):
        """ Handle ARP requests and send spoofed ARP responses """
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt.opcode == arp.ARP_REQUEST:
            if arp_pkt.dst_ip == self.red_service_ip or arp_pkt.dst_ip == self.blue_service_ip:
                self.send_arp_reply(datapath, eth, arp_pkt, in_port)

    def send_arp_reply(self, datapath, eth, arp_pkt, in_port):
        """ Send an ARP reply spoofing the service MAC """
        pkt = packet.Packet()
        ether = ethernet.ethernet(dst=eth.src, src=self.service_mac, ethertype=ether_types.ETH_TYPE_ARP)
        arp_reply = arp.arp(opcode=arp.ARP_REPLY, src_mac=self.service_mac, src_ip=arp_pkt.dst_ip, dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip)
        pkt.add_protocol(ether)
        pkt.add_protocol(arp_reply)
        pkt.serialize()

        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        datapath.send_msg(out)

    def handle_ipv4(self, datapath, pkt, eth, ip_pkt, in_port):
        """ Handle IPv4 packets and load balance between servers """
        if ip_pkt.dst == self.red_service_ip:
            server = self.get_next_server(self.red_servers, 'red')
        elif ip_pkt.dst == self.blue_service_ip:
            server = self.get_next_server(self.blue_servers, 'blue')
        else:
            return  # Not our service IP

        # Set up flow for client-server communication
        self.install_flow(datapath, eth, ip_pkt, server, in_port)

    def install_flow(self, datapath, eth, ip_pkt, server, in_port):
        """ Install flow for a client request to be forwarded to a chosen server """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Match client request (service IP as destination)
        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_pkt.dst)

        # Set actions to rewrite destination IP/MAC to server
        actions = [
            parser.OFPActionSetField(ipv4_dst=server['ip']),
            parser.OFPActionSetField(eth_dst=server['mac']),
            parser.OFPActionOutput(server['port'])
        ]
        self.add_flow(datapath, 1, match, actions)

    def get_next_server(self, server_list, service_type):
        """ Choose the next server using round-robin """
        if service_type == 'red':
            server = server_list[self.red_index]
            self.red_index = (self.red_index + 1) % len(server_list)
        else:
            server = server_list[self.blue_index]
            self.blue_index = (self.blue_index + 1) % len(server_list)
        return server
