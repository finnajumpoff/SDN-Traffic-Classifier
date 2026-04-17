from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

# Logger for printing messages in POX terminal
log = core.getLogger()


# This class handles one switch connection
class TrafficClassifier(object):

  # Runs when a switch connects
  def __init__(self, connection):

    # Save switch connection
    self.connection = connection

    # Register PacketIn listener
    connection.addListeners(self)

    # Stores learned MAC addresses and their ports
    # Example: {MAC : port}
    self.mac_to_port = {}


  # Called when switch sends unknown packet to controller
  def _handle_PacketIn(self, event):

    # Parse packet
    packet = event.parsed

    # Ignore bad packets
    if not packet.parsed:
      return


    # Learn source MAC address location
    self.mac_to_port[packet.src] = event.port


    # Protocol Classification
    if packet.type == ethernet.IP_TYPE:

      # Get IP packet inside Ethernet frame
      ip_p = packet.payload

      # ICMP = ping traffic
      if ip_p.protocol == ipv4.ICMP_PROTOCOL:
        log.info("Classified ICMP from %s" % (ip_p.srcip))

      # TCP traffic
      elif ip_p.protocol == ipv4.TCP_PROTOCOL:
        log.info("Classified TCP from %s" % (ip_p.srcip))

      # UDP traffic
      elif ip_p.protocol == ipv4.UDP_PROTOCOL:
        log.info("Classified UDP from %s" % (ip_p.srcip))


    # If destination MAC is known
    if packet.dst in self.mac_to_port:

      # Get output port
      out_port = self.mac_to_port[packet.dst]

      # Create flow rule
      msg = of.ofp_flow_mod()

      # Match similar packets
      msg.match = of.ofp_match.from_packet(packet, event.port)

      # Delete rule after 10 sec inactivity
      msg.idle_timeout = 10

      # Forward packet to correct port
      msg.actions.append(
        of.ofp_action_output(port=out_port)
      )

      # Also forward current packet immediately
      msg.data = event.ofp

      # Send rule to switch
      self.connection.send(msg)

    else:
      # Destination unknown, flood packet

      msg = of.ofp_packet_out()

      msg.actions.append(
        of.ofp_action_output(port=of.OFPP_FLOOD)
      )

      # Add packet data
      msg.data = event.ofp

      # Incoming port
      msg.in_port = event.port

      # Send flood command
      self.connection.send(msg)

# Called when module starts
def launch():

  # Runs when switch connects
  def start_switch(event):

    log.info("Controlling switch %s" % (event.connection,))

    # Create controller object
    TrafficClassifier(event.connection)


  # Listen for switch connections
  core.openflow.addListenerByName(
    "ConnectionUp",
    start_switch
  )
