from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3
import logging
logging.basicConfig(level=logging.DEBUG)

from collections import defaultdict

class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        # define your own attributes and states maintained by the controller
        with open('lb_config.json') as f:
            self.config = json.load(f)
        
        # map of client to server 
        self.client_to_server = dict()

        # map of server to a list of clients assigned to each server 
        self.server_to_client = defaultdict(list)

        # service ips of red and blue servers
        self.blue_service_ip = self.config['service_ips']['blue']
        self.red_service_ip = self.config['service_ips']['red']

        # actual ips of red and blue servers
        self.blue_servers_ips = self.config['service_ips']['blue']
        self.blue_servers_ips = self.config['service_ips']['red']

    """
    broadcast the request to the server ips to receive output port
    """
    def send_arp_requests(self, dp):
        pass
		    
    def send_proxied_arp_response(self):
        # relay arp response to clients or servers
        # no need to insert entries into the flow table
        # WRITE YOUR CODE HERE
        pass
	
    """
    when the client is making request not for the first time
    """
    def send_proxied_arp_request(self):
        # relay arp requests to clients or servers
        # no need to insert entries into the flow table
        # WRITE YOUR CODE HERE
        pass
         
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
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        dp_id = datapath.id

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # handle arp packets
            if src in client_to_server.keys():
                self.send_proxied_arp_request()
            else:
                self.send_arp_requests(dp=datapath)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            # handle ip packets
            # WRITE YOUR CODE HERE
    

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        # handle FlowRemoved event	
        # WRITE YOUR CODE HERE
