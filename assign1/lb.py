from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import lldp, ether_types
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

        self.service_mac = self.config['service_mac']

        # actual ips of red and blue servers
        self.h5_ip = self.config['server_ips']['blue'][0]
        self.h6_ip = self.config['server_ips']['blue'][1]
        self.h7_ip = self.config['server_ips']['red'][0]
        self.h8_ip = self.config['server_ips']['red'][1]
        self.ip_to_output_port = dict()
        self.ip_to_mac = dict()
        self.client_ip_to_mac = dict()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow_entry(datapath, 0, match, actions, 0)

    def send_arp_requests(self, dp, src, dst, msg):
        # handle load balancing
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        if dst == self.blue_service_ip:
            print(f'    This request is BLUE')
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
            print('    IT WILL BE BROADCASTED')
            out_port = ofproto.OFPP_FLOOD
        print(f'     Destination ip is {dst_ip} and output port is {out_port}')

        # modify the destination ip to actual ip of the corresponding server
        # update the MAC address as well if known
        actions = [
            parser.OFPActionSetField(arp_tpa=dst_ip),
        ]
        if dst_ip in self.ip_to_mac.keys():
            actions.append(parser.OFPActionSetField(
                arp_tha=self.ip_to_mac[dst_ip]))
        actions.append(parser.OFPActionOutput(out_port))

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = None

        print(f'destination is {dst_ip} and {out_port}')

        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions, data=data)
        dp.send_msg(out)

    def send_proxied_arp_response(self, dp, src_mac, src_ip, dst_ip, msg):
        print('ARP RESPONSE')
        self.ip_to_mac[src_ip] = src_mac
        self.ip_to_output_port[src_ip] = msg.match['in_port']
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        if src_ip == self.h5_ip or src_ip == self.h6_ip:
            src = self.blue_service_ip
        elif src_ip == self.h7_ip or src_ip == self.h8_ip:
            src = self.red_service_ip
        print(f'src mac is {self.service_mac} and src ip is {src}')
        actions = [
            parser.OFPActionSetField(arp_spa=src),
            parser.OFPActionSetField(arp_sha=self.service_mac),
            parser.OFPActionOutput(self.client_ip_to_mac[dst_ip])
        ]
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions, data=msg.data)
        dp.send_msg(out)

    def send_ip_response(self, dp, src_mac, src_ip, dst_ip, msg):
        print('IP RESPONSE')
        self.ip_to_mac[src_ip] = src_mac
        self.ip_to_output_port[src_ip] = msg.match['in_port']
        parser = dp.ofproto_parser
        if src_ip == self.h5_ip or src_ip == self.h6_ip:
            src = self.blue_service_ip
        elif src_ip == self.h7_ip or src_ip == self.h8_ip:
            src = self.red_service_ip

        actions = [
            parser.OFPActionSetField(ipv4_src=src),
            parser.OFPActionSetField(eth_src=self.service_mac),
        ]
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions, data=msg.data)
        dp.send_msg(out)

    def send_proxied_arp_request(self, dp, src, dst, msg):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        if dst == self.blue_service_ip:
            dst_ip = self.client_to_blue_server[src]
        else:
            dst_ip = self.client_to_red_server[src]

        if dst_ip in self.ip_to_output_port.keys():
            out_port = self.ip_to_output_port[dst_ip]
        else:
            # broadcast the msg if out port is unknown
            out_port = ofproto.OFPP_FLOOD
        # modify the destination ip to actual ip of the corresponding server
        actions = [
            parser.OFPActionSetField(arp_tpa=dst_ip)
        ]

        # update the MAC address as well if known
        if dst_ip in self.ip_to_mac.keys():
            actions.append(parser.OFPActionSetField(
                arp_tha=self.ip_to_mac[dst_ip]))

        actions.append(parser.OFPActionOutput(out_port))

        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions, data=msg.data)
        dp.send_msg(out)

    def send_ip_request(self, dp, src_mac, dst_mac, src_ip, dst_ip, msg):
        print('IP REQUEST')
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        if dst_ip == self.blue_service_ip:
            src_service_ip = self.blue_service_ip
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
            src_service_ip = self.red_service_ip
            if src_ip in self.client_to_red_server.keys():
                dst_server_ip = self.client_to_red_server[src_ip]
            else:
                if len(self.server_to_client[self.h7_ip]) < len(self.server_to_client[self.h8_ip]):
                    self.server_to_client[self.h7_ip].append(src_ip)
                    self.client_to_red_server[src_ip] = self.h7_ip
                else:
                    self.server_to_client[self.h8_ip].append(src_ip)
                    self.client_to_red_server[src_ip] = self.h8_ip
                dst_server_ip = self.client_to_red_server[src_ip]

        if dst_server_ip in self.ip_to_output_port.keys():
            out_port = self.ip_to_output_port[dst_server_ip]
        else:
            return

        # modify the destination ip to actual ip of the corresponding server
        actions_request = [
            parser.OFPActionSetField(ipv4_dst=dst_server_ip),
        ]

        # update the MAC address if known
        if dst_server_ip in self.ip_to_mac.keys():
            actions_request.append(parser.OFPActionSetField(
                eth_dst=self.ip_to_mac[dst_server_ip]))
        else:
            return

        actions_request.append(parser.OFPActionOutput(out_port))

        actions_response = [
            parser.OFPActionSetField(ipv4_src=src_service_ip),
            parser.OFPActionSetField(eth_src=self.service_mac),
            parser.OFPActionOutput(msg.match['in_port'])
        ]

        match_request = parser.OFPMatch(
            in_port=msg.match['in_port'], eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
        match_response = parser.OFPMatch(
            in_port=out_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=src_ip)

        self.add_flow_entry(dp, 1, match_request, actions_request)
        self.add_flow_entry(dp, 1, match_response, actions_response)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions_request, data=data)
        dp.send_msg(out)

    def add_flow_entry(self, datapath, priority, match, actions, timeout=10):
        # helper function to insert flow entries into flow table
        # by default, the idle_timeout is set to be 10 seconds
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if timeout == 0:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, idle_timeout=timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        print('Arrived')
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
            if src_ip in self.server_to_client.keys():
                print(
                    f'  This is an ARP Response. src ip is {src_ip} and the dst ip is {dst_ip}')
                self.send_proxied_arp_response(
                    dp=datapath, src_mac=src_mac, src_ip=src_ip, dst_ip=dst_ip, msg=msg)
            elif (src_ip in self.client_to_blue_server.keys() and dst_ip == self.blue_service_ip) or (src_ip in self.client_to_red_server.keys() and dst_ip == self.red_service_ip):
                self.client_ip_to_mac[src_ip] = in_port
                self.send_proxied_arp_request(
                    dp=datapath, src=src_ip, dst=dst_ip, msg=msg)
            else:
                print(
                    f'  This is an ARP Reuqest. src ip is {src_ip} and the dst ip is {dst_ip}')
                self.client_ip_to_mac[src_ip] = in_port
                self.send_arp_requests(
                    dp=datapath, src=src_ip, dst=dst_ip, msg=msg)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt, _, _ = pkt_type.parser(pkt_data)
            src_ip, dst_ip = ipv4_pkt.src, ipv4_pkt.dst
            print(f'src ip of ip request is {src_ip}')
            if src_ip in self.server_to_client.keys():
                self.send_ip_response(
                    dp=datapath, src_mac=src_mac, src_ip=src_ip, dst_ip=dst_ip, msg=msg)
            else:
                self.client_ip_to_mac[src_ip] = in_port
                self.send_ip_request(
                    dp=datapath, src_mac=src_mac, dst_mac=dst_mac, src_ip=src_ip, dst_ip=dst_ip, msg=msg)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        # handle FlowRemoved event
        print('FLOW REMOVED EVENT')
        pass
