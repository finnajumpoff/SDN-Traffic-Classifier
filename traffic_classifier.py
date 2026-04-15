from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()

class TrafficClassifier (object):
  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)
    self.mac_to_port = {} 

  def _handle_PacketIn (self, event):
    packet = event.parsed
    if not packet.parsed: return

    # 1. MAC Learning
    self.mac_to_port[packet.src] = event.port

    # 2. Protocol Classification (The Assignment Logic)
    if packet.type == ethernet.IP_TYPE:
      ip_p = packet.payload
      if ip_p.protocol == ipv4.ICMP_PROTOCOL:
        log.info("Classified ICMP from %s" % (ip_p.srcip))
      elif ip_p.protocol == ipv4.TCP_PROTOCOL:
        log.info("Classified TCP from %s" % (ip_p.srcip))
      elif ip_p.protocol == ipv4.UDP_PROTOCOL:
        log.info("Classified UDP from %s" % (ip_p.srcip))

    # 3. Forwarding Decision & Execution
    if packet.dst in self.mac_to_port:
      out_port = self.mac_to_port[packet.dst]
      
      # Destination known: Install a flow rule AND forward the current packet
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      msg.idle_timeout = 10 # Rule expires so you can test repeatedly
      msg.actions.append(of.ofp_action_output(port = out_port))
      
      # CRITICAL FIX: Tell switch to apply this to the currently buffered packet
      msg.data = event.ofp 
      self.connection.send(msg)

    else:
      # Destination unknown (e.g., ARP Request): Flood it using packet_out
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

def launch ():
  def start_switch (event):
    log.info("Controlling switch %s" % (event.connection,))
    TrafficClassifier(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
