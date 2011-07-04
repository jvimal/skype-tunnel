import socket
import select
import termcolor as T
import argparse
from subprocess import Popen, PIPE
import sys
import traceback

def cmd(c):
    print T.colored(c, 'yellow')
    p = Popen(c, shell=True, stdout=PIPE)
    out = p.stdout.read()
    p.wait()
    return out

ipfw_rule_num = 1
def ipfw(c):
    global ipfw_rule_num
    cmd("ipfw add %d %s" % (ipfw_rule_num, c))
    ipfw_rule_num += 1

def log(s):
    print T.colored(s, "yellow")
    sys.stdout.flush()

def info(s):
    print T.colored(s, "grey", attrs=['bold'])

def error(s):
    print T.colored(s, "red", attrs=['bold'])

def check(pkt):
    hdr = pkt[0:20] # assume IP hdr is 20B long for now
    s = 0
    for i in xrange(0, 20, 2):
        s += hdr[i] + (hdr[i+1] << 8)
    s = (s & 0xFFFF) + ((s >> 16) & 0xFFFF)
    s = s + (s >> 16)
    s = (~s) & 0xFFFF
    return s

def ip_check(data):
    pkt = map(ord, data)
    pkt[10] = 0
    pkt[11] = 0
    s = check(pkt)
    pkt[10] = (s & 0x00FF)
    pkt[11] = (s & 0xFF00) >> 8
    return ''.join(map(chr, pkt))

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("google.com", 80))
    addr = s.getsockname()
    s.close()
    log("Using local IP %s" % addr[0])
    return addr[0]

parser = argparse.ArgumentParser(description='Setup skype tunnel')
parser.add_argument('--divert_port',
                    help="diver socket's port number",
                    dest='divert_port',
                    action='store',
                    default='6666')

parser.add_argument('--local-ip', '-i',
                    help="machine's local IP address",
                    dest="local_ip",
                    action="store",
                    required=False,
                    default="128.12.146.43")

parser.add_argument('--dest', '-d',
                    help="filter packets to this destination (ip:port)",
                    dest='dest',
                    action='store',
                    default=None)

parser.add_argument('--src', '-s',
                    help="filter packets from this source (ip:port)",
                    dest="src",
                    action="store",
                    default=None)

parser.add_argument('--skype_port',
                    help="skype app's port to tunnel it to",
                    dest="skype_port",
                    action="store",
                    default="9000")

parser.add_argument('-v', '--verbose',
                    dest="verbose",
                    action="store_true",
                    help="Verbose output showing details about packets tunneled and received.",
                    default=False)

parser.add_argument('--server',
                    dest="server",
                    action="store_true",
                    help="Function in server mode.",
                    default=False)

args = parser.parse_args()
if args.dest is None and args.src is None and args.server == False:
    parser.print_help()
    sys.exit(0)

args.local_ip = get_local_ip()

skype_relay_addr = ('127.0.0.1', int(args.skype_port))
our_addr = ('127.0.0.1', int(args.skype_port) + 1)
raw_addr = ('0.0.0.0', int(args.divert_port))
our_control_addr = ('127.0.0.1', 10001)

"""
The experiment:

1. Start skype on two computers A and B

2. Run skype.py on both the computers A and B.
   On A: python skype.py -u B -n test
   On B: python skype.py -u A -n test

3. The skype clients have connected to each other.  Now, tunnel.py is
   the program that captures IP packets and tunnels them via skype.

   On A: python tunnel.py --local-ip A --dest B:22
   On B: python tunnel.py --local-ip B --src B:22 (server mode)
    (or) python tunnel.py --server
"""

def setup_ipfw():
    if args.dest:
        if ':' in args.dest:
            dest_ip, dest_port = args.dest.split(':')
            if dest_port == 'any':
                dest_port = ''
        else:
            dest_ip = args.dest
            dest_port = '22'
        ipfw("divert %s tcp from any to %s %s" % (args.divert_port, dest_ip, dest_port))
        ipfw("deny all from any to %s" % (dest_ip))
    elif args.src or args.server:
        if args.server:
            args.src = get_local_ip()
        if ':' in args.src:
            src_ip, src_port = args.src.split(':')
            if src_port == 'any':
                src_port = ''
        else:
            src_ip = args.src
            src_port = '22'
        ipfw("divert %s tcp from %s %s to any" % (args.divert_port, src_ip, src_port))

def main():
    # setup filters
    setup_ipfw()
    log("Creating raw socket")
    # create raw socket
    rawsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 254)
    rawsock.bind(raw_addr)

    # socket to talk to skype
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(our_addr)
    sock.settimeout(2)

    # socket that programs can use to talk to us
    controlsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    controlsock.bind(our_control_addr)

    log("Registering with skype")
    # register with 1 byte message to skype
    while 1:
        sock.sendto("1", skype_relay_addr)
        try:
            data, addr = sock.recvfrom(4096)
        except socket.error:
            log("retrying...")
            continue
        if data == "2":
            log("Registration successful.")
            break

    # just read packets and send to skype
    inputs = [rawsock, sock, controlsock]

    # read packets from skype, and inject into network stack
    # Shouldn't timeout here, as we're using select()
    while 1:
        ins, outs, excs = select.select(inputs, [], [])
        for inp_sock in ins:
            if inp_sock == rawsock:
                # read from kernel
                data, addr = rawsock.recvfrom(4096)
                # compute checksum; most inefficient thing to do in Python
                data = ip_check(data)
                # send to skype
                if args.verbose:
                    info("tx %d bytes to skype" % len(data))
                sock.sendto(data, skype_relay_addr)
            elif inp_sock == sock:
                # read from skype
                data, addr = sock.recvfrom(4096)
                # send to kernel
                # TODO: should we make this packet behave as a packet that was
                # rx-ed or one that was tx-ed from this machine?
                if len(data) > 20:
                    if args.verbose:
                        log("rx %d bytes from skype" % len(data))
                    rawsock.sendto(data, (args.local_ip, 10000))
            elif inp_sock == controlsock:
                data, addr = controlsock.recvfrom(4096)
                if len(data) == 2:
                    log("got shutdown message from %s" % (addr,))
                    cmd("ipfw delete 1 2")
                return
            else:
                error("wrong socket")
    return

try:
    main()
except:
    error(traceback.format_exc())
    cmd("ipfw delete 1 2")
