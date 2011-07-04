import Skype4Py as Skype
try:
    import termcolor as T
except:
    T = None
import argparse
from time import sleep
import sys, traceback
import socket
import select
import random
import threading
import base64
import signal

# Note: There's some bug and this python script
# has to be run in 32 bit mode for it to work.

# Note2: May not be the most efficient, but it
# works for now.

def log(s):
    if T:
        print T.colored(s, "yellow")
    else:
        print s
    sys.stdout.flush()
    return None

def info(s):
    if T:
        print T.colored(s, "green", attrs=['bold'])
    else:
        print s

def error(s):
    if T:
        print T.colored(s, "red", attrs=['bold'])
    else:
        print s

parser = argparse.ArgumentParser(description='Tunneling through skype.')
parser.add_argument('--user', '-u',
                    dest='user',
                    action='store',
                    help="The Skype username to connect to",
                    required=False,
                    default=None)

parser.add_argument('--listen', '-l',
                    dest="addr",
                    action="store",
                    help="Port to listen on.  Will bind to localhost:port.",
                    default='localhost:9000')

parser.add_argument('-n', '--name',
                    dest="name",
                    action="store",
                    help="Application name.  Will default to 'xyz' if not provided. " +
                    "Note: This name should match at the two end points!",
                    default='xyz')

parser.add_argument('-v', '--verbose',
                    dest="verbose",
                    action="store_true",
                    help="Enable verbose output.  Will show info about received and transmitted bytes.",
                    default=False)

parser.add_argument('-i', '--ip',
                    dest="local_ip",
                    action="store",
                    help="Our local IP address",
                    required=False)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("google.com", 80))
    addr = s.getsockname()
    s.close()
    log("Using local IP %s" % addr[0])
    return addr[0]

args = parser.parse_args()
host, portstr = args.addr.split(':')
args.addr = (host, int(portstr))
args.local_ip = get_local_ip()

def sighandler(signum, frame):
    global app
    log("Caught signal")
    if app:
        app.close()
    sys.exit(0)
    return

signal.signal(signal.SIGTERM, sighandler)

def get_dest(pkt):
    # Just return the src IP for now
    # TODO: return src IP and src PORT (for dealing with NATed clients)
    return pkt[16:20]

def get_src(pkt):
    # Just return the src IP for now
    # TODO: return src IP and src PORT (for dealing with NATed clients)
    return pkt[12:16]

class App:
    """Main interactions with our skype app."""

    def __init__(self, rx_callback=None, conn_callback=None):
        self.rx_callback = rx_callback
        self.conn_callback = conn_callback
        s = Skype.Skype()
        log("Attaching event handler")
        s.RegisterEventHandler('ApplicationDatagram', self.ApplicationDatagram)
        s.RegisterEventHandler('ApplicationConnecting', self.ApplicationConnecting)
        s.RegisterEventHandler('ApplicationStreams', self.ApplicationStreams)

        log("Attaching to Skype program")
        s.Attach()

        self.s = s
        if args.name:
            self.name = args.name
        else:
            rand = random.randrange(0, 1 << 30)
            self.name = "test%d" % rand
        self.app = self.s.Application(self.name)
        self.app.Create()
        self.running = True
        log("Created application %s" % (self.name))
        self.stream_for_user = {}
        self.pending_users = []

    def connect(self, username, wait=False, retry=False):
        log("Connecting to user:%s" % username)
        tries = 0
        stream = self.app.Connect(username, WaitConnected=wait)
        self.pending_users.append(username)
        if wait and stream != None:
            self.stream_for_user[username] = stream
            self.pending_users.remove(username)
            log("Connected to user:%s" % username)
        if retry:
            while username in self.pending_users:
                sleep(2)
                log("retrying...")
                self.app.Connect(username, WaitConnected=wait)

    def ApplicationConnecting(self, app, users):
        pass

    def ApplicationStreams(self, app, streams):
        log("Application stream change")
        for stream in streams:
            handle = stream.PartnerHandle
            log("New stream for: %s" % handle)
            self.stream_for_user[handle] = stream
            if self.conn_callback:
                self.conn_callback(handle)
            if handle in self.pending_users:
                self.pending_users.remove(handle)

    def username(self):
        return self.s.CurrentUser.Handle

    def send(self, user, msg):
        encoded = base64.b64encode(msg)
        if len(encoded) > 1400:
            error("discarding large packet length = %d" % len(encoded))
            return
        stream = self.stream_for_user.get(user)
        if stream is not None:
            return stream.SendDatagram(encoded)

    def ApplicationDatagram(self, app, stream, text):
        data = base64.b64decode(text)
        if self.rx_callback:
            # If we have a listener
            self.rx_callback(user=stream.PartnerHandle, data=data)
        return data

    def close(self):
        if self.running:
            self.app.Delete()
            self.running = False

    def __del__(self):
        if self.running:
            self.app.Delete()
            self.running = False

def Server():
    """
    Creates a Skype UDP server.  Any data sent to this server will
    come out of the peer at the other end.  Any data received from the
    server will be sent to the "listener" (usually, a local listener).
    No guarantee for reliability or in-order delivery and hence best
    suited for IP packets.

    Takes care of base64 encoding the datagram.
    """
    global app, ip_to_user
    # An IP:port destination is mapped to a Skype destination username
    # This is basically a simple NAT!
    ip_to_user.update({})
    log("Creating appsocket for Skype datagrams")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(args.addr)
    listener = None

    def rx_callback(user=None, data=None):
        """This function will be called in a separate thread by
        Skype4Py, when we receive data from user."""
        if user:
            # TODO: Should we do this everytime?
            user_addr = get_src(data)
            if args.verbose:
                log("Receiving from src %r, len=%d" % (user_addr, len(data)))
            ip_to_user[user_addr] = user
        if user and len(data) == 4:
            log("Got remote IP address = %r from user %s" % (data, user))
            ip_to_user[data] = user
            return
        if listener:
            sock.sendto(data, listener)
        return

    def conn_callback(user):
        """This function is called when we receive a new
        connection."""
        log("Got connection request from %s" % user)
        for i in xrange(5):
            app.send(user, socket.inet_aton(args.local_ip))
            sleep(1)
        return

    MAX_SIZE = 4096
    app = App(rx_callback=rx_callback, conn_callback=conn_callback)
    if args.user:
        #post_connect_request(app.username(), args.user)
        app.connect(args.user, retry=True)
        # Send our IP address 5 times :)
        for i in xrange(5):
            log("Sending our IP address")
            app.send(args.user, socket.inet_aton(args.local_ip))
            sleep(1)
    while 1:
        data, addr = sock.recvfrom(MAX_SIZE)

        # Much less than a min sized IP packet, so it must be a
        # control message
        if len(data) == 1:
            log("New listener %s replaces old listener %s" % (addr, listener))
            listener = addr
            sock.sendto("2", addr)
            continue
        if len(data) == 2:
            log("Got shutdown message from %s" % (addr,))
            app.close()
            return
        user_addr = get_dest(data)
        user = ip_to_user.get(user_addr, None)
        if user is not None:
            if args.verbose:
                info("Sending to %r, len=%d" % (user_addr, len(data)))
            app.send(user, data)
        else:
            error("Destination `%r' does not have any registered Skype user." % (user_addr))

try:
    app = None
    ip_to_user = {}
    #thread = threading.Thread(target=Listener)
    #thread.setDaemon(True)
    #thread.start()
    Server()
except:
    print "Exception:"
    print '-'*60
    error(traceback.format_exc())
    print '-'*60
    app.close()
