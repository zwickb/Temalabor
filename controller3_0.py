""""
2. meresi feladat

start as: ./pox.py log.color log.level --feladat2=DEBUG feladat2 proto.arp_responder portstat
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.addresses import IPAddr, EthAddr
import time


log = core.getLogger()

H1_IP = '10.0.0.1'
H2_IP = '10.0.0.2'
H3_IP = '10.0.0.3'
H4_IP = '10.0.0.4'
H5_IP = '10.0.0.5'
H6_IP = '10.0.0.6'
H1_MAC = '00:00:00:00:00:01'
H2_MAC = '00:00:00:00:00:02'
H3_MAC = '00:00:00:00:00:03'
H4_MAC = '00:00:00:00:00:04'
H5_MAC = '00:00:00:00:00:05'
H6_MAC = '00:00:00:00:00:06'
S1_DPID = 1
S2_DPID = 2
S3_DPID = 3
S4_DPID = 4
f=open('rules.txt','r')

if False:
     # PORTS -- ovs
     S1_H1 = 2
     S1_H2 = 3
     S1_S4 = 1
     S2_H3 = 2
     S2_H4 = 3
     S2_S4 = 1
     S3_H5 = 2
     S3_H6 = 3
     S3_S4 = 1
     S4_S1 = 1
     S4_S2 = 2
     S4_S3 = 3
else:
    # PORTS -- user switch
    S1_H1 = 2
    S1_H2 = 3
    S1_S4 = 1
    S2_H3 = 2
    S2_H4 = 3
    S2_S4 = 1
    S3_H5 = 2
    S3_H6 = 3
    S3_S4 = 1
    S4_S1 = 1
    S4_S2 = 2
    S4_S3 = 3


    # ###########################################################################

    class ProactiveRouting(object):

        def __init__(self, arg1):
            # We want to hear PacketIn messages, so we listen
            # to the connection
            core.openflow.addListeners(self)

            log.debug("Initializing ProactiveRouting, arg1=%s" % (arg1,))
            self.logged_adresses = []
            self.saved_adresses = []
            self.blocked_adresses = []
            self.db_arp = {H1_IP: H1_MAC,
                      H2_IP: H2_MAC,
                      H3_IP: H3_MAC,
                      H4_IP: H4_MAC,
                      H5_IP: H5_MAC,
                      H6_IP: H6_MAC}

            self.db = {S1_DPID: {H1_MAC: S1_H1,
                            H2_MAC: S1_H2,
                            H3_MAC: S1_S4,
                            H4_MAC: S1_S4,
                            H5_MAC: S1_S4,
                            H6_MAC: S1_S4},
                  S2_DPID: {H1_MAC: S2_S4,
                            H2_MAC: S2_S4,
                            H3_MAC: S2_H3,
                            H4_MAC: S2_H4,
                            H5_MAC: S2_S4,
                            H6_MAC: S2_S4},
                  S3_DPID: {H1_MAC: S3_S4,
                            H2_MAC: S3_S4,
                            H3_MAC: S3_S4,
                            H4_MAC: S3_S4,
                            H5_MAC: S3_H5,
                            H6_MAC: S3_H6},
                  S4_DPID: {H1_MAC: S4_S1,
                            H2_MAC: S4_S1,
                            H3_MAC: S4_S2,
                            H4_MAC: S4_S2,
                            H5_MAC: S4_S3,
                            H6_MAC: S4_S3}}
            self.read_rules()

            for ip, mac in self.db_arp.iteritems():
                core.Interactive.variables['arp'].set(ip, mac)

        def read_rules(self):

            for line in f:
                s=line.split()
                codeword=s[0]
                adresstype=s[1]
                adress=s[2]
                if adresstype == 'mac':
                    adress=adress
                elif adresstype  == 'ip':
                    for tmpip,tmpmac in self.db_arp.iteritems():
                        if tmpip == adress:
                            adress = tmpmac
                else:
                    log.error("Illegal expression in rules, adresstype=%s" % (adresstype))
                if codeword=='BlockDestination':
                    self.blocked_adresses.append(adress)
                elif codeword=='Log':
                    self.logged_adresses.append(adress)
                elif codeword== 'Save':
                    self.saved_adresses.append(adress)
                else:
                    log.error("Illegal command in rules:%s"%codeword)



        def _handle_PacketIn (self,event):
            packet=event.parsed
            rawdata=event.data
            dst_mac=packet.dst
            converted=str(dst_mac)
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet)
            msg.idle_timeout = 5
            msg.buffer_id = event.ofp.buffer_id
            for mac, porta in self.db[event.dpid].iteritems():
                if mac ==converted:
                    msg.actions.append(of.ofp_action_output(port=porta))
            if converted in self.blocked_adresses:
                log.debug("Blocked a packet")
                return
            elif converted in self.logged_adresses:
                log.debug("Logged a packet")
                f= open("log.txt","a")
                f.write("Incoming packet to %s on switch:%s \n" %(converted,dpid_to_str(event.dpid)))
                event.connection.send(msg)
                return
            elif converted in self.saved_adresses:
                log.debug("Saved a packet")
                f=open("saved.pcap","ab")
                f.write(rawdata)
                event.connection.send(msg)
                return
            else:
		event.connection.send(msg)
                return



        def _handle_ConnectionUp(self, event):
            log.debug("ConnectionUp, dpid=%s" % (event.dpid))

            for mac, porta in self.db[event.dpid].iteritems():
                if mac in self.blocked_adresses:
                    log.debug("Blocked a flow in dpid=%s" %(event.dpid))
                    #msg = of.ofp_flow_mod()
                    #msg.match.dl_dst = EthAddr(mac)
                    #msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
                    #event.connection.send(msg)
                elif mac in self.logged_adresses:
                    log.debug("Started logging a flow in dpid=%s" % (event.dpid))
                    #msg = of.ofp_flow_mod()
                    #msg.match.dl_dst = EthAddr(mac)
                    #msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
                    #event.connection.send(msg)
                elif mac in self.saved_adresses:
                    log.debug("Started saving a flows data in dpid=%s" % (event.dpid))
                    #msg = of.ofp_flow_mod()
                    #msg.match.dl_dst = EthAddr(mac)
                    #msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
                    #event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.match.dl_dst = EthAddr(mac)
                    msg.actions.append(of.ofp_action_output(port= porta))
                    event.connection.send(msg)


    # ###########################################################################


    def launch(arg1=True):
        """
        Starts a controller.
        """

        def init():
            core.registerNew(ProactiveRouting, arg1)
        core.call_when_ready(init, ['ARPResponder', 'PortStat'])
