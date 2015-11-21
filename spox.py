"""
A security POX component

This is security POX component. This component implements end-to-end
security for POX controller.

For running this module just type "./pox.py spox".
If you want specify file with whitelist,
use "./pox.py spox --whitelist="/path/to/whitelist".

For see this message type "./pox.py help --spox".
"""

# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library

# Create a logger for this component
log = core.getLogger()


def _go_up (event):
  """
  And when we started...
  """
  log.info("SPOX application ready (to do nothing).")


@poxutil.eval_args
def launch (whitelist = "../whitelist.txt"):
  """
  First-launch function
  """

  log.warn("Whitelist: %s (%s)", whitelist, type(whitelist))
  core.addListenerByName("UpEvent", _go_up)


def breakfast ():
  """
  Serves a Pythonic breakfast
  """
  # You can invoke other functions from the commandline too.  We call
  # these multiple or alternative launch functions.  To execute this
  # one, you'd do:
  # ./pox.py skeleton:breakfast

  import random
  items = "egg,bacon,sausage,baked beans,tomato".split(',')
  random.shuffle(items)
  breakfast = items[:random.randint(0,len(items))]
  breakfast += ['spam'] * random.randint(0,len(breakfast)+1)
  random.shuffle(breakfast)
  if len(breakfast) == 0: breakfast = ["lobster thermidor aux crevettes"]

  log.warn("Breakfast is served:")
  log.warn("%s and spam", ", ".join(breakfast))
