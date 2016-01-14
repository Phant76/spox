"""
A security POX component

This is security POX component. This component implements end-to-end
security for POX controller.

For running this module just type "./pox.py spox".
If you want specify file with topology file,
use "./pox.py spox --topology="/path/to/topology".

Format of topology file:
[switch]
1 2 # dpids for switches, for example: 1 2 3 4 5 9 87 76 65
[connection]
# If PC, when: [dpid of connected switch] 0 [IPv4] [IPv6] [MAC] [Security]
1 0 10.0.0.1 fe80::200:ff:fe00:101 00:00:00:00:01:01 high
2 0 10.0.0.2 fe80::200:ff:fe00:102 00:00:00:00:01:02 low
# If switch, when: [dpid of connected switch] [dpid of second switch]
1 2
# It's all!
'#' is working too

For see this message type "./pox.py help --spox".
"""

# Import some POX stuff
from pox.core import core                               # Main POX object
import pox.openflow.libopenflow_01 as of                # OpenFlow 1.0 library
import pox.openflow.of_01 as of_01                      # OpenFlow 1.0 obj
import pox.lib.packet as pkt                            # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr, IPAddr6  # Address types
import pox.lib.util as poxutil                          # Various util functions
import pox.lib.revent as revent                         # Event library
import pox.lib.recoco as recoco                         # Multitasking library

class SpoxPC (object):
  ipv4 = None
  ipv6 = None
  mac = None
  security = None

  def __init__(self, ipv4, ipv6, mac, security):
    self.ipv4 = IPAddr(ipv4)
    self.ipv6 = IPAddr6(ipv6)
    self.mac = EthAddr(mac)
    self.security = security

class SpoxSwitch (object):
  ports = []
  dpid = None
  sec_context = None
  spox_topology = None
  spox = None
  connection = None

  def __init__(self, spox_topology, dpid):
    self.spox_topology = spox_topology
    self.spox = spox_topology.spox
    self.dpid = dpid
    self.msg("Initialisation complete.")

  def add_computer(self, ipv4, ipv6, mac, security):
    if security not in Spox.security_levels or security is Spox.NONE_SEC:
      self.msg("Strange level of security: %s. Changed to %s." % (security, Spox.security_levels[0]))
      security = Spox.security_levels[0]
    self.ports.append(SpoxPC(ipv4, ipv6, mac, security))
    self.msg("Computer added:")
    self.msg("IPv4: %s" % ipv4)
    self.msg("IPv6: %s" % ipv6)
    self.msg("MAC: %s" % mac)
    self.msg("Security: %s" % security)
    self.msg("Port: %s" % (len(self.ports) - 1))

  def add_switch(self, dpid):
    self.ports.append(self.spox_topology.switches[dpid])
    self.msg("Added switch %s to port %s." % (dpid, len(self.ports) - 1))
    self.spox_topology.switches[dpid].ports.append(self)
    self.spox_topology.switches[dpid].msg("Added switch %s to port %s." %
                                          (self.dpid, len(self.spox_topology.switches[dpid].ports) - 1))

  def set_connection(self, new_connection):
    self.connection = new_connection
    self.connection.addListeners(self, priority=99)
    self.msg("Connection established.")

  def _handle_PacketIn (self, event):
    address = None
    # For ipv4
    ip = event.parsed.find("ipv4")
    if ip is not None:
      address = ip.srcip
    else:
      # For ipv6
      ip = event.parsed.find("ipv6")
      if ip is not None:
        address = ip.srcip
      else:
        # For ethernet
        eth = event.parsed.find("ethernet")
        if eth is not None:
          address = eth.src
    # If it isn't of these types - skip
    if address is None:
      self.sec_context = None
      return
    # Set context based on src address
    self.sec_context = self.spox_topology.security(address)
    self.msg("Context: %s. Address: %s" % (self.sec_context, address))

  def _handle_DataSended (self, event):
    data = event.data
    data_type = None
    # If we can't define context - skip it
    if self.sec_context is None:
      return
    # If it will be OpenFlow message - parse it!
    if isinstance(data, of.ofp_header):
      if isinstance(data, of.ofp_packet_out):
        # If we see ofp_packet_out - check it!
        self.check_output(data)
      if isinstance(data, of.ofp_flow_mod):
        # If we see ofp_flow_mod - check it!
        self.check_modify(data)
    # Else - we do not need check this data - skip it.

  def check_output(self, ofp_packet_output):
    self.msg("We have a output packet! Check actions...")
    security = {self.sec_context}
    # TODO: must we check in_port?
    for action in ofp_packet_output.actions:
      if isinstance(action, of.ofp_action_output):
        if action.port == of.OFPP_IN_PORT:
          # It's safe to put it back
          continue
        if action.port == of.OFPP_TABLE:
          # If rule already on switch - it's has been checked.
          continue
        if action.port == of.OFPP_NORMAL:
          # If rule is legasy installed - trust them.
          continue
        if action.port == of.OFPP_CONTROLLER:
          # It's safe - controllers are good device!
          continue
        if action.port == of.OFPP_LOCAL:
          # Aww... I can't understand this. TODO: Read wiki again!
          continue
        if action.port == of.OFPP_FLOOD or action.port == of.OFPP_ALL:
          # Oh, awful. Ok, let's check this...
          self.msg("Flood action.")
          for port in self.ports:
            security = security.intersection(self.spox.rule_output_once(self.sec_context, self.dpid, port))
          if len(security) == 0:
            self.msg("Bad action! Data will be dropped!")
            raise AssertionError
          continue
        if action.port < 0xFF00:
          # It's normal physical port. Check this.
          self.msg("Out to physical port action.")
          if action.port < len(self.ports):
            security = security.intersection(self.spox.rule_output_once(self.sec_context,
                                                                        self.dpid,
                                                                        self.ports[action.port - 1]))
          else:
            self.msg("Port %s is empty in topology! May be topology is incorrect?" % action.port)
          if len(security) == 0:
            self.msg("Bad action! Data will be dropped!")
            raise AssertionError
          continue
        self.msg("It mustn't be reached!")
        raise ReferenceError
      if isinstance(action, of.ofp_action_dl_addr):
        if action.type is of.OFPAT_SET_DL_SRC:
          self.msg("Set ethernet source address action.")
          security = security.intersection(self.spox.rule_set_src_once(self.sec_context, action.dl_addr))
          if len(security) == 0:
            self.msg("Bad action! Data will be dropped!")
            raise AssertionError
          continue
        if action.type is of.OFPAT_SET_DL_DST:
          self.msg("Set ethernet destination address action.")
          security = security.intersection(self.spox.rule_set_dst_once(self.sec_context, action.dl_addr))
          if len(security) == 0:
            self.msg("Bad action! Data will be dropped!")
            raise AssertionError
          continue
        self.msg("It mustn't be reached!")
        raise ReferenceError
      if isinstance(action, of.ofp_action_nw_addr):
        if action.type is of.OFPAT_SET_NW_SRC:
          self.msg("Set IP source address action.")
          security = security.intersection(self.spox.rule_set_src_once(self.sec_context, action.nw_addr))
          if len(security) == 0:
            self.msg("Bad action! Data will be dropped!")
            raise AssertionError
          continue
        if action.type is of.OFPAT_SET_NW_DST:
          self.msg("Set ethernet destination address action.")
          security = security.intersection(self.spox.rule_set_dst_once(self.sec_context, action.nw_addr))
          if len(security) == 0:
            self.msg("Bad action! Data will be dropped!")
            raise AssertionError
          continue
        self.msg("It mustn't be reached!")
        raise ReferenceError
      # Else it is a safe action, pass
    if self.sec_context in security:
      self.msg("This rules may be typed as %s. Actions end." % self.sec_context)
      return
    self.msg("It's a bad rules! Droping data...")
    raise AssertionError

  def check_modify(self, ofp_flow_modify):
    self.msg("We have a modify packet! Check matches...")
    security = {self.sec_context}
    match = ofp_flow_modify.match
    src_match = dst_match = None
    # Try to search match TODO: make it works with wildcard!!!
    if match.dl_src is not None:
      src_match = [match.dl_src]
    else:
      if match.get_nw_src()[0] is not None and match.get_nw_src()[0] is 0:
        src_match = [match.get_nw_src()[0]]
      else:
        src_match = None
    if match.dl_dst is not None:
      dst_match = [match.dl_dst]
    else:
      if match.get_nw_dst()[0] is not None and match.get_nw_dst()[0] is 0:
        dst_match = [match.get_nw_dst()[0]]
      else:
        dst_match = None
    # And we see on command.
    if ofp_flow_modify.command is of.OFPFC_ADD:
      self.msg("It's a adding/modify packet. Let's look closer...")
      for action in ofp_flow_modify.actions:
        if isinstance(action, of.ofp_action_output):
          if action.port == of.OFPP_IN_PORT:
            # It's safe to put it back
            continue
          if action.port == of.OFPP_TABLE:
            # If rule already on switch - it's has been checked.
            continue
          if action.port == of.OFPP_NORMAL:
            # If rule is legasy installed - trust them.
            continue
          if action.port == of.OFPP_CONTROLLER:
            # It's safe - controllers are good device!
            continue
          if action.port == of.OFPP_LOCAL:
            # Aww... I can't understand this. TODO: Read wiki again!
            continue
          if action.port == of.OFPP_FLOOD or action.port == of.OFPP_ALL:
            # Oh, awful. Ok, let's check this...
            self.msg("Flood action.")
            for port in self.ports:
              security = security.intersection(self.spox.rule_output(src_match, dst_match, self.dpid, port))
            if len(security) == 0:
              self.msg("Bad action! Data will be dropped!")
              raise AssertionError
            continue
          if action.port < 0xFF00:
            # It's normal physical port. Check this.
            self.msg("Out to physical port action.")
            if action.port < len(self.ports):
              security = security.intersection(self.spox.rule_output(src_match,
                                                                     dst_match,
                                                                     self.dpid,
                                                                     self.ports[action.port - 1]))
            else:
              self.msg("Port %s is empty in topology! May be topology is incorrect?" % action.port)
            if len(security) == 0:
              self.msg("Bad action! Data will be dropped!")
              raise AssertionError
            continue
          self.msg("It mustn't be reached!")
          raise ReferenceError
        if isinstance(action, of.ofp_action_dl_addr):
          if action.type is of.OFPAT_SET_DL_SRC:
            self.msg("Set ethernet source address action.")
            security = security.intersection(self.spox.rule_set_src(src_match, action.dl_addr))
            if len(security) == 0:
              self.msg("Bad action! Data will be dropped!")
              raise AssertionError
            continue
          if action.type is of.OFPAT_SET_DL_DST:
            self.msg("Set ethernet destination address action.")
            security = security.intersection(self.spox.rule_set_dst(src_match, action.dl_addr))
            if len(security) == 0:
              self.msg("Bad action! Data will be dropped!")
              raise AssertionError
            continue
          self.msg("It mustn't be reached!")
          raise ReferenceError
        if isinstance(action, of.ofp_action_nw_addr):
          if action.type is of.OFPAT_SET_NW_SRC:
            self.msg("Set IP source address action.")
            security = security.intersection(self.spox.rule_set_src(src_match, action.nw_addr))
            if len(security) == 0:
              self.msg("Bad action! Data will be dropped!")
              raise AssertionError
            continue
          if action.type is of.OFPAT_SET_NW_DST:
            self.msg("Set ethernet destination address action.")
            security = security.intersection(self.spox.rule_set_dst(src_match, action.nw_addr))
            if len(security) == 0:
              self.msg("Bad action! Data will be dropped!")
              raise AssertionError
            continue
          self.msg("It mustn't be reached!")
          raise ReferenceError
        # Else it is a safe action, pass
      if self.sec_context in security:
        self.msg("This rules may be typed as %s. Actions end." % self.sec_context)
        return
      self.msg("It's a bad rules! Droping data...")
      raise AssertionError
    if ofp_flow_modify.command is of.OFPFC_DELETE or ofp_flow_modify.command is of.OFPFC_DELETE_STRICT:
      self.msg("It's a adding/modify packet. Let's look closer...")
      #TODO: Delete

  def msg(self, msg):
    self.spox_topology.msg("Switch %s: %s" % (self.dpid, msg))


class SpoxTopology (object):
  switches = {}
  spox = None
  high = {}
  searched = [] # For reachable

  def __init__(self, spox, topology_file):
    self.spox = spox
    self.high['ipv4'] = []
    self.high['ipv6'] = []
    self.high['ethernet'] = []

    try:
      topology = open(topology_file)
      stage = ""
      switches = []
      for line in topology:
        if line[0] == '#':
          # If comment line - skip it.
          continue
        if line[0] == '[':
          stage = line.strip()
          self.msg("Stage: %s" % stage)
          continue
        if stage == "[switch]":
          new_switches = line.split(' ')
          for new_switch in new_switches:
            if new_switch[0] == '#':
              # If comment line - skip it.
              break
            if new_switch in switches:
              self.msg("Two switches with one dpid %s!" % new_switch)
              raise SyntaxError
            switches.append(new_switch)
            self.switches[int(new_switch)] = SpoxSwitch(self, int(new_switch))
          continue
        if stage == "[connection]":
          new_connection = line.split(' ')
          dpid = int(new_connection[0])
          dev_id = int(new_connection[1])
          if dev_id == 0:
            ipv4 = IPAddr(new_connection[2])
            ipv6 = IPAddr6(new_connection[3])
            mac = EthAddr(new_connection[4])
            security = new_connection[5].strip()
            self.switches[dpid].add_computer(ipv4, ipv6, mac, security)
            if security == Spox.HIGH_SEC:
              computer = self.switches[dpid].ports[-1]
              self.add_to_high_security(computer.ipv4, computer.ipv6, computer.mac)
          else:
            self.switches[dpid].add_switch(dev_id)
          continue
        self.msg("Syntax error on file %s!" % topology_file)
        raise SyntaxError
    except:
      self.spox.log.info("Can't read topology in file %s." % topology_file)
      raise IOError

  def add_to_high_security(self, ipv4, ipv6, mac):
    self.high['ipv4'].append(ipv4)
    self.high['ipv6'].append(ipv6)
    self.high['ethernet'].append(mac)

  def is_high(self, addr):
    if isinstance(addr, IPAddr):
      return addr in self.high['ipv4']
    if isinstance(addr, IPAddr6):
      return addr in self.high['ipv6']
    if isinstance(addr, EthAddr):
      return addr in self.high['ethernet']

  def security(self, addr):
    if self.is_high(addr):
      return Spox.HIGH_SEC
    return Spox.LOW_SEC

  def is_reachable(self, dpid, port, security):
    # For loops. It's not a cure, but with it we shall not going on circle.
    if dpid in self.searched:
      return False
    self.searched.append(dpid)
    # And we start search!
    if isinstance(port, SpoxPC):
      # If it's a PC - check the security.
      if port.security is security:
        self.searched = []
        return True
    else:
      # Else it's a switch. Let's look on it!
      for remote_port in port.ports:
        if self.is_reachable(port.dpid, remote_port, security):
          return True
    # We not find anything and go out...
    self.searched.remove(dpid)
    return False

  def msg(self, msg):
    self.spox.msg("Topology: %s" % msg)


class Spox (object):
  _core_name = 'SPOX'
  log = core.getLogger()
  # Types of security
  security_levels = ['low', 'high', 'none']
  LOW_SEC = security_levels[0]
  HIGH_SEC = security_levels[1]
  NONE_SEC = security_levels[2]
  # Our topology
  topology = None

  def __init__ (self, topology_path):
    self.msg("Initialize end-to-end security for POX...")
    # Get out topology from file on topology_path
    self.topology = SpoxTopology(self, topology_path)
    # Get listen for new connections
    core.openflow.addListeners(self)
    self.msg("SPox is ready.")

  def _handle_ConnectionUp(self, event):
    self.topology.switches[event.dpid].set_connection(event.connection)

  def forall(self, addresses):
    if addresses is None:
      return set([Spox.HIGH_SEC, Spox.LOW_SEC])
    is_high = self.topology.is_high(addresses[0])
    for address in addresses:
      if self.topology.is_high(address) != is_high:
        return set()
    if is_high:
      # Rule 2
      return {Spox.HIGH_SEC}
    # Rule 1
    return {Spox.LOW_SEC}

  def exists(self, addresses):
    if addresses is None:
      return {Spox.HIGH_SEC}
    for address in addresses:
      if self.topology.is_high(address):
        # Rule 3
        return {Spox.HIGH_SEC}
    return set()

  def exists_reachable(self, dpid, port, security):
    if self.topology.is_reachable(dpid, port, security):
      return {security}
    return set()

  def rule_drop(self, src_match):
    # Rule 5
    return self.forall(src_match)

  def rule_output_once(self, context, dpid, port):
    type_of_output = set()
    # Rule 6
    if Spox.HIGH_SEC in self.exists_reachable(dpid, port, Spox.HIGH_SEC):
      type_of_output.update({Spox.HIGH_SEC})
    # Rule 7
    if context is Spox.LOW_SEC:
      type_of_output.update({Spox.LOW_SEC})
    return type_of_output

  def rule_output(self, src_match, dst_match, dpid, port):
    type_of_output = set()
    # Rule 6
    if Spox.HIGH_SEC in self.exists(dst_match) and Spox.HIGH_SEC in self.exists_reachable(dpid, port, Spox.HIGH_SEC):
      type_of_output.update({Spox.HIGH_SEC})
    # Rule 7
    if Spox.LOW_SEC in self.forall(src_match):
      type_of_output.update({Spox.LOW_SEC})
    return type_of_output

  def rule_delete(self, src_match, dst_match):
    type_of_delete = set()
    # Rule 8
    if Spox.HIGH_SEC in self.forall(dst_match):
      type_of_delete.update({Spox.HIGH_SEC})
    # Rule 9
    if Spox.LOW_SEC in self.forall(src_match):
      type_of_delete.update({Spox.LOW_SEC})
    return type_of_delete

  def rule_set_src_once(self, context, new_src):
    type_of_set = set()
    # Rule 10
    if context is Spox.LOW_SEC and new_src is Spox.LOW_SEC:
      type_of_set.update({Spox.LOW_SEC})
    # Rule 11
    if context is Spox.HIGH_SEC and new_src is Spox.HIGH_SEC:
      type_of_set.update({Spox.HIGH_SEC})
    return type_of_set

  def rule_set_src(self, src_match, src_pattern):
    type_of_set = set()
    # Rule 10
    if Spox.LOW_SEC in self.forall(src_match) and Spox.LOW_SEC in self.forall(src_pattern):
      type_of_set.update({Spox.LOW_SEC})
    # Rule 11
    if Spox.HIGH_SEC in self.forall(src_match) and Spox.HIGH_SEC in self.forall(src_pattern):
      type_of_set.update({Spox.HIGH_SEC})
    return type_of_set

  def rule_set_dst_once(self, context, new_dst):
    type_of_set = set()
    # Rule 10
    if context is Spox.LOW_SEC:
      type_of_set.update({Spox.LOW_SEC})
    # Rule 11
    if context is Spox.HIGH_SEC and new_dst is Spox.HIGH_SEC:
      type_of_set.update({Spox.HIGH_SEC})
    return type_of_set

  def rule_set_dst(self,src_match, dst_pattern):
    type_of_set = set()
    # Rule 10
    if Spox.LOW_SEC in self.forall(src_match):
      type_of_set.update({Spox.LOW_SEC})
    # Rule 11
    if Spox.HIGH_SEC in self.forall(src_match) and Spox.HIGH_SEC in self.forall(dst_pattern):
      type_of_set.update({Spox.HIGH_SEC})
    return type_of_set

  def rule_set(self, src_match, src_pattern, dst_pattern):
    type_of_set = set()
    # Rule 10
    if Spox.LOW_SEC in self.forall(src_match) and Spox.LOW_SEC in self.forall(src_pattern):
      type_of_set.update({Spox.LOW_SEC})
    # Rule 11
    if Spox.HIGH_SEC in self.forall(src_match) and \
            Spox.HIGH_SEC in self.forall(src_pattern) and Spox.HIGH_SEC in self.forall(dst_pattern):
      type_of_set.update({Spox.HIGH_SEC})
    return type_of_set

  def msg(self, msg):
    self.log.info(msg)


def launch (topology="./topology.txt"):
  # Register SPox with topology
  core.registerNew(Spox, topology)
