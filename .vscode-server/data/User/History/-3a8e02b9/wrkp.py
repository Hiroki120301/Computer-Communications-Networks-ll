from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3

import json
from collections import defaultdict

import logging
logging.basicConfig(level=logging.DEBUG)


class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        # define your own attributes and states maintained by the controller
        with open('lb_config.json') as f:
            self.config = json.load(f)

        # map of client to server
        self.client_to_blue_server = dict()
        self.client_to_red_server = dict()

        # map of server to a list of clients assigned to each server
        self.server_to_client = defaultdict(list)

        # service ips of red and blue servers
        self.blue_service_ip = self.config['service_ips']['blue']
        self.red_service_ip = self.config['service_ips']['red']

        # actual ips of red and blue servers
        self.h5_ip = self.config['service_ips']['blue'][0]
        self.h6_ip = self.config['service_ips']['blue'][1]
        self.h7_ip = self.config['service_ips']['red'][0]
        self.h8_ip = self.config['service_ips']['red'][1]

        self.ip_to_output_port = dict()
        self.ip_to_mac = dict()

    def send_arp_requests(self, dp, src, dst, msg):
        # handle load balancing
        if dst == self.blue_service_ip:
            if len(self.server_to_client[self.h5_ip]) < len(self.server_to_client[self.h6_ip]):
                self.server_to_client[self.h5_ip].append(src)
                self.client_to_blue_server[src] = self.h5_ip
            else:
                self.server_to_client[self.h6_ip].append(src)
                self.client_to_blue_server[src] = self.h6_ip
            dst_ip = self.client_to_blue_server[src]
        else:
            if len(self.server_to_client[self.h7_ip]) < len(self.server_to_client[self.h8_ip]):
                self.server_to_client[self.h7_ip].append(src)
                self.client_to_red_server[src] = self.h7_ip
            else:
                self.server_to_client[self.h8_ip].append(src)
                self.client_to_red_server[src] = self.h8_ip
            dst_ip = self.client_to_red_server[src]

        # check if dst_ip to out_port mapping exists
        if dst_ip in self.ip_to_output_port.keys():
            out_port = self.ip_to_output_port[dst_ip]
        else:
            # broadcast the msg if out port is unknown
            out_port = ofproto.OFPP_FLOOD

        # modify the destination ip to actual ip of the corresponding server
        actions = [
            parser.OFPActionOutput(out_port),
            parser.OFPActionSetField(arp_tpa=dst_ip)
        ]

        # update the MAC address as well if known
        if dst_ip in self.ip_to_mac.keys():
            actions.append(parser.OFPActionSetField(
                arp_tha=self.ip_to_mac[dst_ip]))

        # construct out packet
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def send_proxied_arp_response(self):
        # relay arp response to clients or servers
        # no need to insert entries into the flow table
        # WRITE YOUR CODE HERE

    def send_proxied_arp_request(self, dp, src, dst, msg):
        if dst == self.blue_service_ip:
            dst_ip = self.client_to_blue_server[src]
        else:
            dst_ip = self.client_to_red_server[src]

        out_port = self.ip_to_output_port[dst_ip]
        # modify the destination ip to actual ip of the corresponding server
        actions = [
            parser.OFPActionOutput(out_port),
            parser.OFPActionSetField(arp_tpa=dst_ip)
        ]

        # update the MAC address as well if known
        if dst_ip in self.ip_to_mac.keys():
            actions.append(parser.OFPActionSetField(
                arp_tha=self.ip_to_mac[dst_ip]))

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def handle_ip_request(dp, src, dst, src_ip, dst_ip, msg):
        if dst_ip == self.blue_service_ip:
            if src_ip in self.client_to_blue_server.keys():
                dst_server_ip = self.client_to_blue_server[src_ip]
            else:
                if len(self.server_to_client[self.h5_ip]) < len(self.server_to_client[self.h6_ip]):
                    self.server_to_client[self.h5_ip].append(src)
                    self.client_to_blue_server[src_ip] = self.h5_ip
                else:
                    self.server_to_client[self.h6_ip].append(src_ip)
                    self.client_to_blue_server[src_ip] = self.h6_ip
                dst_server_ip = self.client_to_blue_server[src_ip]
        else:
            if src_ip in self.client_to_red_server.keys():
                dst_server_ip = self.client_to_red_server[src_ip]
            else:
                if len(self.server_to_client[self.h7_ip]) < len(self.server_to_client[self.h8_ip]):
                    self.server_to_client[self.h7_ip].append(src)
                    self.client_to_red_server[src] = self.h7_ip
                else:
                    self.server_to_client[self.h8_ip].append(src)
                    self.client_to_red_server[src] = self.h8_ip
                dst_ip = self.client_to_red_server[src]
        
        if 
        

    def add_flow_entry(self, datapath, priority, match, actions, timeout=10):
        # helper function to insert flow entries into flow table
        # by default, the idle_timeout is set to be 10 seconds
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        eth, pkt_type, pkt_data = ethernet.ethernet.parser(msg.data)

        src_mac, dst_mac = eth.src, eth.dst
        dp_id = datapath.id

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt, _, _ = pkt_type.parser(pkt_data)
            src_ip, dst_ip = arp_pkt.src_ip, arp_pkt.dst_ip
            if (src_ip in client_to_blue_server.keys() and dst_ip == self.blue_service_ip) or (src_ip in client_to_red_server.keys() and dst_ip == self.red_service_ip):
                self.send_proxied_arp_request(
                    dp=datapath, src=src_ip, dst=dst_ip, msg=msg)
            else:
                self.send_arp_requests(dp=datapath, src=src_ip, dst=dst_ip, msg=msg)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt, _, _ = pkt_type.parser(pkt_data)
            src_ip, dst_ip = ipv4_pkt.src, ipv4_pkt.dst
            self.handle_ip_request(dp=datapath, src=src, dst=dst, src_ip=src_ip, dst_ip=dst_ip, msg=msg)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        # handle FlowRemoved event
        pass
