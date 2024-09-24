from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3


class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        # define your own attributes and states maintained by the controller
        # WRITE YOUR CODE HERE

    def send_arp_requests(self, dp):
        # send arp requests to servers to learn their mac addresses
        # WRITE YOUR CODE HERE

		    
    def send_proxied_arp_response(self):
        # relay arp response to clients or servers
        # no need to insert entries into the flow table
        # WRITE YOUR CODE HERE
	

    def send_proxied_arp_request(self):
        # relay arp requests to clients or servers
        # no need to insert entries into the flow table
        # WRITE YOUR CODE HERE
         
    def add_flow_entry(self, datapath, priority, match, actions, timeout=10):
        # helper function to insert flow entries into flow table
        # by default, the idle_timeout is set to be 10 seconds
        # WRITE YOUR CODE HERE
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(in_port=port,
                                                 eth_dst=dst,
                                                 eth_src=src)
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)
	
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        mac_dst = eth.dst
        mac_src = eth.src
        
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # handle arp packets
            # WRITE YOUR CODE HERE
        
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            # handle ip packets
            # WRITE YOUR CODE HERE

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        # handle FlowRemoved event	
        # WRITE YOUR CODE HERE
