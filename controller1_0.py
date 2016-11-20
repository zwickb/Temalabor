"""
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
f=open('rules','r')
db_arp={}
db={}
logged_adresses=[]
saved_adresses=[]
blocked_adresses=[]

if False:
    # PORTS -- ovs
    S1_H1 = 1
    S1_H2 = 2
    S1_S4 = 3
    S2_H3 = 1
    S2_H4 = 2
    S2_S4 = 3
    S3_H5 = 1
    S3_H6 = 2
    S3_S4 = 3
    S4_S1 = 1
    S4_S2 = 2
    S4_S3 = 3
else:
    # PORTS -- user switch
    S1_H1 = 1
    S1_H2 = 2
    S1_S4 = 3
    S2_H3 = 4
    S2_H4 = 1
    S2_S4 = 2
    S3_H5 = 3
    S3_H6 = 4
    S3_S4 = 1
    S4_S1 = 2
    S4_S2 = 3
    S4_S3 = 4


# ###########################################################################

class ProactiveRouting(object):

    def __init__(self, arg1):
        # We want to hear PacketIn messages, so we listen
        # to the connection
        core.openflow.addListeners(self)

        log.debug("Initializing ProactiveRouting, arg1=%s" % (arg1,))

        db_arp = {H1_IP: H1_MAC,
                  H2_IP: H2_MAC,
                  H3_IP: H3_MAC,
                  H4_IP: H4_MAC,
                  H5_IP: H5_MAC,
                  H6_IP: H6_MAC}

        db = {S1_DPID: {H1_MAC: S1_H1,
                        H2_MAC: S2_H2,
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

        for ip, mac in db_arp.iteritems():
            core.Interactive.variables['arp'].set(ip, mac)

    def Read_Rules(self):
        for line in f:
            s=line.split()
            codeword=s[0]
            adresstype=s[1]
            adress=s[2]
            for ip, mac in db_arp.iteritems():
                if adresstype == 'mac':
                    adress=adress
                elif adresstype == 'ip':
                    for tmpip, tmpmac in db_arp:
                        if tmpmac == adress:
                            adress = tmpip
                            break
                else:
                    log.debug("Illegal expression in rules, adresstype=%s" % (adresstype))
            if codeword=='BlockDestination':
                blocked_adresses.append(adress)
            elif codeword=='Log':
                logged_adresses.append(adress)
            elif codeword== 'Save':
                saved_adresses.append(adress)
            else:
                log.debug("Illegal command in rules:%s"%codeword)



    def __handle_PacketIn (self,event):
        packet=event.parsed
        dst_mac=packet.dst
        converted_mac=str(dst_mac)
        dpid=dpid_to_str(event.dpid )
        if converted_mac in blocked_adresses:
            log.debug("Blocked a packet")
        elif dst_mac in logged_adresses:
            f= open("log","a")
            f.write("Incoming packet to %s on switch: %s" %(converted_mac,dpid))
            msg= of.ofp_packet_out()
            msg.buffer_id=event.ofp.buffer_id



    def _handle_ConnectionUp(self, event):
        log.debug("ConnectionUp, dpid=%s" % (event.dpid))

        for mac, porta in db[event.dpid].iteritems():
            if mac in blocked_adresses:
                log.debug("Blocked a flow in dpid=%s" %(event.dpid))
            elif mac in logged_adresses:
                log.debug("Started logging a flow in dpid=%s" % (event.dpid))
            elif mac in saved_adresses:
                log.debug("Started saving a flows data in dpid=%s" % (event.dpid))
            else:
                msg = of.ofp_flow_mod()
                msg.match.dl_dst = EthAddr(mac)
                msg.actions.append(of.ofp_action_output(port=porta))
                event.connection.send(msg)


# ###########################################################################


def launch(arg1=True):
    """
    Starts a controller.
    """

    def init():
        core.registerNew(ProactiveRouting, arg1)
    core.call_when_ready(init, ['ARPResponder', 'PortStat'])