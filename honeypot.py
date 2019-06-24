# Author: Thanh Tong, OPSC-540-85
# Final project - HTTPS/telnet Honeypot

from socket import socket, AF_INET, SOCK_STREAM
import ssl, sys, time, os.path, ConfigParser, uuid, Queue, sqlite3, plotly
from string import *
from thread import *
from scapy.all import *
from p0f import P0f, P0fException
from plotly.graph_objs import Scatter, Layout


KEYFILE = 'server_key.pem'   # Private key of the server
CERTFILE = 'server_cert.pem' # Server certificate
WEBHDR200 = ('HTTP/1.1 200 OK\nContent-Type: text/html\n\n')
WEBHDR404 = ('HTTP/1.1 404 Not Found\nContent-Type: text/html\n\n')
WEBHDR403 = ('HTTP/1.1 403 Forbidden\nContent-Type: text/html\n\n')
EXITAPP = False
INTERACTIONS = Queue.Queue(maxsize=0)

# gets content from file to server to client
def get_content_file(prefix, filename):
    dirloc = 'data/' + prefix   # content files should be in data directory

    if os.path.exists(dirloc+filename): # serve requested content if file exists
        homepage_fd = open(dirloc + filename, 'r') # returns content from corresponding file in data/ directory
    elif prefix == 'web-':                         # serve 404 error file content if request comes from web server
        homepage_fd = open(dirloc + '404.txt', 'r')
    else:
        return ''

    homepage_val = homepage_fd.read()   # read in file
    homepage_fd.close()
    return homepage_val                 # return content


# function handles HTTP request from client and provides response back
# supports GET, POST, HEAD methods
def webserver_response(s, p, config_obj):
    requestcmd = ''     # stores HTTP command from client (santized)
    originalcmd = ''    # stores HTTP command from client
    filecontent = ''    # HTTP payload from server to client
    numrec = 0          # tracks received message
    homepage = config_obj.get('web_srv', 'default_page')    # get filename for starting page
    headresp = ''       # header response
    prefix = 'web-'
    method_obj = {'type': 'http-request'}

    while not EXITAPP:  # run forever
        numrec = numrec + 1
        data = s.recv(1024)     # receives up to 1K bytes of data
        if data != b'':         # continue unless null byte
            # command from client is sometimes sent over multiple messages
            requestcmd = requestcmd + strip(data)   #strip whitespace. workaround for chrome browser
            originalcmd = originalcmd + data        #unmodified command from client

            # check that it is the end of request query AND that it is a GET method
            if '\r\n\r\n' in originalcmd and 'GET' in requestcmd:
                # parse for GET resource value
                GET_resource = requestcmd.split(' HTTP/')
                GETURL = GET_resource[0][4:]
                resourcename = GETURL[1:].split('?')[0]
                method_obj['function'] = resourcename
                # client requested "home" page
                if resourcename == '' or resourcename == 'home':
                    filecontent = get_content_file(prefix, homepage)
                    headresp = WEBHDR200
                # client requested some page that exists
                elif (resourcename) in config_obj.get('web_srv', 'content_pages'):
                    filecontent = get_content_file(prefix, resourcename + '.txt')
                    headresp = WEBHDR200
                # client requested unknown page
                else:
                    filecontent = get_content_file(prefix, '404.txt')
                    headresp = WEBHDR404

                # send response to client
                s.send(headresp + filecontent)
                INTERACTIONS.put({'type': 'http-response', 'message': 'Respond to GET request from client',
                                  'time': time.strftime('%X %x'),'respond-to': requestcmd, 'ip':p[0]})
                break
            # check that it is the end of request query AND that it is a POST method
            elif '\r\n\r\n' in originalcmd and 'POST' in requestcmd:
                # parse for content length and how much content has been received so far
                contentlengthval = requestcmd.split('Content-Length: ')
                contentlength = int(contentlengthval[1].split('\r\n')[0]) if len(contentlengthval)>1 else 0
                #contentval = requestcmd.split('\r\n\r\n')
                contentval = originalcmd.split('\r\n\r\n')
                #print('***contentval =' + repr(contentval))
                contentrecv = len(contentval[1]) if len(contentval)>1 else 0
                #print('***content length:%s\trecv:%s' % (contentlength, contentrecv))

                # continue getting messages from client until we receive all content
                while contentrecv < contentlength:
                    moredata = s.recv(1024)
                    contentrecv = contentrecv + len(moredata)   # update received counter
                    #print('***content recv:' + str(contentrecv))
                    requestcmd = requestcmd + strip(moredata)   # update HTTP command
                    originalcmd = originalcmd + moredata
                    #print('***moredata:' + repr(moredata))
                    #print('***orig/request', originalcmd, requestcmd)

                #contentval = requestcmd.split('\r\n\r\n')
                contentval = originalcmd.split('\r\n\r\n')

                # parse HTTP command to figure out what client is requesting and respond appropriately
                # POST is primarily used for simulating client login
                # create appropriate HTTP response
                if 'commit=Reset' in requestcmd:
                    filecontent = get_content_file(prefix, homepage)
                    headresp = WEBHDR200
                    method_obj['function'] = 'reset password'
                elif 'commit=Login' in requestcmd:      # user attempting to login
                    #print(repr(requestcmd))
                    # get username and password from POST data
                    #print('***contentval=',contentval)
                    login_credential = contentval[1].split('&') if (len(contentval)>1) else [contentval,'']
                    login_username = login_credential[0][6:] if (len(login_credential[0])>6) else ''
                    login_password = login_credential[1][9:] if (len(login_credential[1])>9) else ''
                    # verify login credentials and respond with the welcome page or access denied page as appropriate
                    if(handle_authentication(login_username, login_password, config_obj, p[0])):
                        filecontent = get_content_file(prefix, 'welcome.txt')
                        headresp = WEBHDR200
                    else:
                        filecontent = get_content_file(prefix, '403.txt')
                        headresp = WEBHDR403
                    method_obj['function'] = 'login'
                else:   # this is an unknown POST. respond with access denied.
                    filecontent = get_content_file(prefix, '403.txt')
                    headresp = WEBHDR403
                    method_obj['function'] = 'unknown'

                # send response to client
                s.send(headresp + filecontent)
                INTERACTIONS.put({'type': 'http-response', 'message': 'Respond to POST request from client',
                              'time': get_time(), 'respond-to':requestcmd, 'ip':p[0]})
                break

            # check that it is the end of request query AND that it is a HEAD method
            elif '\r\n\r\n' in originalcmd and 'HEAD' in requestcmd:
                # parse for HEAD resource value
                HEAD_resource = requestcmd.split(' HTTP/')
                HEADURL = HEAD_resource[0][5:]
                resourcename = HEADURL[1:].split('?')[0]
                #print('*** URL:' + repr(HEADURL))
                #print('*** URL1:' + repr(resourcename))

                # client requested home page
                if resourcename == '' or resourcename == 'home':
                    headresp = WEBHDR200
                # content page
                elif (resourcename) in config_obj.get('web_srv', 'content_pages'):
                    headresp = WEBHDR200
                else:   # unavailable page
                    headresp = WEBHDR404

                # send response to client
                s.send(headresp)
                method_obj['function']=resourcename
                INTERACTIONS.put({'type': 'http-response', 'message': 'Respond to HTTP HEAD request from client',
                              'time': get_time(), 'respond-to':requestcmd, 'ip':p[0]})
                break
            else:   # request looks malformed or we have not received the full request
                INTERACTIONS.put({'type': 'info', 'message': 'Client sent malformed or incomplete request to web server. continue receiving',
                              'time': get_time()})

        # nothing left to receive
        else:
            break

    method_obj['ip']=p[0]
    method_obj['time']=get_time()
    method_obj['command']=repr(originalcmd)
    if('function' not in method_obj): method_obj['function'] = 'unknown'
    INTERACTIONS.put(method_obj)    # add http request to queue
    s.close()                       # log disconnect event
    INTERACTIONS.put({'type': 'client-disconnect', 'message':'Client closed connection to web server','ip':p[0],
                      'time':get_time()})


# sniff some port and write to pcap file; n = number of packets per each pcap file
# n is used to ensure file does not get too large and that we do not lose all packets if
#   program crashes
def record_packets(n, port, verbosity):
    #print('*** Start sniffing')
    INTERACTIONS.put({'type': 'info', 'message':'Starting scapy packet capture on port %s' % port,'time':get_time()})

    while 1:    # sniff forever
        if verbosity == 'high':     # sniff and display each packet in detail
            pkts = sniff(filter='tcp and port ' + str(port), count=n, prn=lambda x: x.show())
        elif verbosity == 'low':    # sniff and display each packet summary
            pkts = sniff(filter='tcp and port ' + str(port), count=n, prn=lambda x: x.summary())
        else:                       # sniff and do not display
            pkts = sniff(filter='tcp and port ' + str(port), count=n)
        # generate unique pcap file name
        pcapfname = 'pcap/port' + str(port) + '-' + str(uuid.uuid4()) + '.pcap'
        wrpcap(pcapfname, pkts)     # write packets to pcap file


# main function. initalizes web server tcp/ssl connections and listens for requests
def handle_webserver(address, config_obj):
    s = socket.socket(AF_INET, SOCK_STREAM)        # initialize tcp socket
    name, port = address
    #print ('*** Web Server starting up on %s port %s\n' % address)
    INTERACTIONS.put({'type': 'info', 'message':'Web Server starting up on %s port %s' % address,'time':get_time()})

    s.bind(address)                         # binds socket to address and port
    s.listen(1)                             # start listening

    capture = config_obj.get('mainset', 'writepcap')
    #print('***writepcap:' + repr(capture))
    # start scapy sniffing and packet capture if capture is enabled in config file
    if capture == 'True':
        pcappackets = config_obj.get('mainset', 'pcappackets')
        if pcappackets:
            pcappackets = int(pcappackets)
        else:
            pcappackets = 100
        sniff_stdout = config_obj.get('mainset', 'sniff_stdout')
        start_new_thread(record_packets, (pcappackets, port, sniff_stdout))

    finger = config_obj.get('mainset', 'p0f') # check if p0f is enabled in config

    # Wrap with an SSL layer requiring SSL cert/private key
    s_ssl = ssl.wrap_socket(s,
                            keyfile=KEYFILE,
                            certfile=CERTFILE,
                            server_side=True
                            )
    #print('### Waiting for a connection on port %s' % port)
    INTERACTIONS.put({'type': 'info', 'message':'Waiting for a connection on port %s' % port,'time':get_time()})
    # Wait for connections
    while 1:
        try:
            c,a = s_ssl.accept()            # accept incoming connection
            #print('Got connection', c, a)
            clientip = a[0]
            conn_obj = {'type':'client-connect','message': 'https', 'ip': clientip,'time':get_time()}
            INTERACTIONS.put(conn_obj)
            # get device fingerprint of the incoming connection, multithreaded
            if(finger == 'True'):
                start_new_thread(fingerprint,(clientip,))
            # handle client request, multithreaded
            start_new_thread(webserver_response, (c, a, config_obj))
        except Exception as e:
            #print('{}: {}'.format(e.__class__.__name__, e))
            INTERACTIONS.put({'type':'error', 'message':'{}: {}'.format(e.__class__.__name__, e), 'time':get_time()})



# function handles telnet requests/responses
def telnet_response(s, p, banner, cmdline, config_obj):
    msgnum = 0
    authenticated = False
    logout = False

    try:
        while not EXITAPP and not authenticated:
            if msgnum == 0:
                s.send(banner.decode('string-escape') + '\nlogin: ')  # send welcome banner and login prompt
            else:
                s.send('\nlogin: ')     # prompt login
            data = s.recv(1024)         # get login value
            if(not data): break         # exit loop if no data received (broken pipe or other connection error)

            my_username = strip(data)
            s.send('\xFF\xFB\x01password: ')    # send IAC WILL ECHO (\xFF\xFB\x01) command along with password prompt.
            s.recv(1024)                        # tells telnet client to suppress echo on client so password
                                                # input does not appear on screen. discards the ensuing IAC acknowledgement
            my_password = strip(s.recv(1024))
            authenticated = handle_authentication(my_username, my_password, config_obj,p[0])

            if not authenticated:
                s.send('\xFF\xFC\x01\nLogin incorrect.')    # send command to resume echo and login error to client
                s.recv(1024)                                # discard IAC response from client
            else:
                s.send(
                    '\xFF\xFC\x01\nWelcome! Type HELP for the command list.\n' + cmdline)  # send IAC WONT ECHO (\xFF\xFC\x01) command along with input prompt.
                # tells telnet client to begin echoing again so user input is displayed
                s.recv(1024)  # discards the ensuing IAC acknowledge from the client
            msgnum = msgnum + 1

        while not EXITAPP and not logout:                               # keep connection alive if honeypot is up
            data = s.recv(1024)                                         # and client has not requested logout
            resp_msg = ''
            if data == b'': # close client connection if no data received
                break
            else:
                method_obj = {'type': 'telnet-cmd','ip': p[0],'time': get_time(),'command':repr(data)}
                telnet_cmd = str(data).strip().split(' ')   # isolate command from client
                if 'help' == telnet_cmd[0].lower():
                    method_obj['function'] = 'help'
                    resp_msg = get_content_file('tel-', 'cmdlist.txt')      # display help text if client sends help command
                elif 'logout' == telnet_cmd[0].lower():                     # client sent logout command
                    method_obj['function'] = 'logout'
                    resp_msg = 'Goodbye!\n'                                 # set logout to True to end client connection
                    logout = True
                elif 'pwd' == telnet_cmd[0].lower():                        # client sent pwd command
                    method_obj['function'] = 'pwd'
                    resp_msg = '~\n'
                elif 'echo' == telnet_cmd[0].lower():                       # client sent echo command
                    method_obj['function'] = 'echo'
                    # send back everything that comes after 'echo '. regex removes some special characters like
                    #   single or double quote, square brackets, back slash
                    resp_msg = re.sub('[^a-zA-Z0-9-_*,. ~!@#$%^&()_\-+={}|;:?/<>]', '', ' '.join(telnet_cmd[1:])) + '\n'
                else:   # client sent some custom command
                    # check if the telnet command exists in the configuration file
                    if (telnet_cmd[0].lower()) in config_obj.get('telnet_srv', 'command_responses'):
                        method_obj['function'] = 'custom-defined'
                        # it does, serve the response from the response file in the data directory
                        resp_msg = get_content_file('tel-', telnet_cmd[0].lower() + '.txt')
                    else:   # command is not supported, send command not found response
                        method_obj['function'] = 'command not found'
                        resp_msg = telnet_cmd[0]+ ': command not found\n'

                if ('function' not in method_obj): method_obj['function'] = 'unknown'
                INTERACTIONS.put(method_obj)

            if not logout:
                s.send(resp_msg + cmdline)  # send response and input prompt
            else:
                s.send(resp_msg)            # send logout response
            msgnum = msgnum + 1

        s.close()
        # log connection event
        INTERACTIONS.put({'type': 'client-disconnect', 'message':'Client closed connection to telnet server','ip':p[0],
                          'time':get_time()})
    except socket.error as e:
        s.close()

        INTERACTIONS.put(
            {'type': 'error', 'message': '{}: {}'.format(e.__class__.__name__, e), 'time': get_time()})


# handles telnet connnections from clients
def handle_telnet(address, config_obj):
    s = socket.socket(AF_INET, SOCK_STREAM)  # initialize tcp socket
    name, port = address
    #print ('*** Telnet Server starting up on %s port %s\n' % address)
    INTERACTIONS.put({'type': 'info', 'message':'Telnet Server starting up on %s port %s' % address,'time':get_time()})
    s.bind(address)  # binds socket to address and port
    s.listen(1)  # start listening

    finger = config_obj.get('mainset', 'p0f') # check if p0f is enabled in config

    capture = config_obj.get('mainset', 'writepcap')
    # start scapy sniffing and packet capture if capture is enabled in config file
    if capture == 'True':
        pcappackets = config_obj.get('mainset', 'pcappackets')
        if pcappackets:
            pcappackets = int(pcappackets)
        else:
            pcappackets = 100
        sniff_stdout = config_obj.get('mainset', 'sniff_stdout')
        # call up scapy sniffing in new thread
        start_new_thread(record_packets, (pcappackets, port, sniff_stdout))

    # get banner and other data from config file to display to client
    banner = config_obj.get('telnet_srv', 'banner')
    cmdline = config_obj.get('authentication', 'username') + ' ' + config_obj.get('telnet_srv', 'input_sym') + ' '

    INTERACTIONS.put({'type':'info','message':'Waiting for a connection on port %s' % port,'time':get_time()})
    # Wait for connections
    while 1:
        try:

            c, a = s.accept()  # accept incoming connection
            #print('Got connection', c, a)
            clientip = a[0]
            conn_obj = {'type': 'client-connect', 'message': 'telnet', 'ip': clientip, 'time':get_time()}
            INTERACTIONS.put(conn_obj)
            # get device fingerprint of the incoming connection, multithreaded
            if finger == 'True':
                start_new_thread(fingerprint,(clientip,))
            # handle client request, multithreaded
            start_new_thread(telnet_response, (c, a, banner, cmdline, config_obj))
        except Exception as e:
            print('{}: {}'.format(e.__class__.__name__, e))


# passive fingerprinting of client using the p0f application
# p0f must be running and listening to the socket file "p0f.sock" in the same directory
# run p0f with command: sudo p0f -s path/to/p0f.sock
def fingerprint(ip):
    data = None
    p0ferror = None
    try:
        p0f = P0f("p0f.sock")
        data = p0f.get_info(str(ip))    # ask p0f for information on specified IP
    except P0fException as e:
        p0ferror = ('p0f caught exception P0fException : %s' % e)
    except socket.error as e:
        p0ferror = ('p0f caught exception socket.error : %s' % e)
    except Exception as e:
        p0ferror = ('p0f caught exception : %s' % e)

    if p0ferror:                        # log p0f error
        INTERACTIONS.put({'type':'error','message':ip + ':' + p0ferror, 'time':get_time()})

    if data:
        fing_obj = {'type':'fingerprint','ip':ip, 'data':data, 'time':get_time()}
        INTERACTIONS.put(fing_obj)      # log fingerprint information

    return data


# function verifies login credential submitted matches the one in configuration file
def handle_authentication(username, password, my_config, identifier):
    authenticated = False
    sys_username = my_config.get('authentication','username')   # get username and password from config file
    sys_password = my_config.get('authentication','password')
    if username == sys_username and password == sys_password:   # test if credentials match
        authenticated = True
    #print('***[%s] Login attempt %s:%s %s' % (get_time(),username, password,'passed' if authenticated else 'failed'))
    auth_object = {'type':'authentication','ip':identifier,'time':get_time(),'username':username,
                   'password':password,'success':authenticated}
    INTERACTIONS.put(auth_object)           # log the authentication event
    return authenticated


def get_time():
    return time.strftime('%Y-%m-%d %X')

# Log device/client interactions and pertinent events
# This function displays all events to stdout and stores them in sqlite3 database
def log_interactions():
    print '*** Starting to monitor and log interactions'
    time.sleep(5)   # sleep for 5 seconds to wait for events to be added to queue
    try:
        db_conn = sqlite3.connect('honeypot.sqlite')    #create/open database file
        cur = db_conn.cursor()
        # create tables for storing events if they do not exist
        cur.execute('CREATE TABLE IF NOT EXISTS authentication (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, type TEXT, time DATETIME,'
                    'username TEXT, password TEXT, success TEXT)')
        cur.execute('CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, type TEXT,'
                    'time DATETIME, data TEXT)')
        cur.execute('CREATE TABLE IF NOT EXISTS general_info (id INTEGER PRIMARY KEY, type TEXT,'
                    'time DATETIME, message TEXT, ip TEXT)')
        cur.execute('CREATE TABLE IF NOT EXISTS server_responses (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, type TEXT,'
                    'time DATETIME, message TEXT, respondto TEXT)')
        cur.execute('CREATE TABLE IF NOT EXISTS client_commands (id INTEGER PRIMARY KEY, type TEXT,'
                    'time DATETIME, ip TEXT, command TEXT, function TEXT)')
        # run forever
        while 1:
            added_stuff = False             # bool tracks if there has been changes for the purpose of committing data to database file
            while not INTERACTIONS.empty(): # continue until the queue is empty
                x = INTERACTIONS.get()      # get event item
                print x['type'].upper(), x  # print to stdout

                if x['type'] == 'authentication':   # authentication event. store data in authentication table
                    cur.execute('INSERT INTO authentication (type, ip, time, username, password, success) VALUES (?,?,?,?,?,?)',
                                (x['type'],x['ip'],x['time'],x['username'],x['password'],x['success']))
                elif x['type'] == 'fingerprint':    # fingerprinting event. store in clients table
                    cur.execute('INSERT INTO clients (type, ip, time, data) VALUES (?,?,?,?)',
                                (x['type'],x['ip'],x['time'],repr(x['data'])))
                elif x['type'] == 'error' or x['type'] == 'info':   # error or information event. store in general_info table
                    cur.execute('INSERT INTO general_info (type, time, message) VALUES (?,?,?)',
                                (x['type'],x['time'],x['message']))
                # client connection event. store in general_info table
                elif x['type'] == 'client-connect' or x['type'] == 'client-disconnect':
                    cur.execute('INSERT INTO general_info (type, time, message, ip) VALUES (?,?,?,?)',
                                (x['type'],x['time'],x['message'],x['ip']))
                elif x['type'] == 'http-response':  # web server response event. store in server_responses table
                    cur.execute('INSERT INTO server_responses (type, time, message, ip, respondto) VALUES (?,?,?,?,?)',
                                (x['type'],x['time'],x['message'],x['ip'],x['respond-to']))
                # telnet or http command from client. store in the client_commands table
                elif x['type'] == 'telnet-cmd' or x['type'] == 'http-request':
                    cur.execute('INSERT INTO client_commands (type, time, command, ip, function) VALUES (?,?,?,?,?)',
                                (x['type'],x['time'],x['command'],x['ip'],x['function']))
                else:
                    print '**** SOMETHING WENT WRONG HERE', x['type']

                INTERACTIONS.task_done()

                added_stuff = True

            if added_stuff: db_conn.commit()
            time.sleep(10)                      # wait 10 seconds until we repeat the loop
    except sqlite3.Error as e:
        print 'Error %s:' % e
    finally:
        if db_conn: db_conn.close()
        log_interactions()


# generates daily metrics report in the "daily" directory.
# the function reports on the last 24 hours of authentication attempts
def daily_trends_report():

    while 1:    # run forever
        xcoord = []
        ycoord = []
        for x in range(-24, 0):     # setup data series (x,y) list for 24 hour block
            xcoord.append(x)
        for y in range(0, 24):
            ycoord.append(0)

        try:
            db_conn = sqlite3.connect('honeypot.sqlite')  # create/open database file
            cur = db_conn.cursor()
            # queries database for entries in authentication table for the last 24 hours
            cur.execute('SELECT id, time FROM authentication WHERE time > date("now","-1 day")')
            all_rows = cur.fetchall()
            #print all_rows  #for debug
        except sqlite3.Error as e:
            print 'Error %s:' % e
        finally:
            if db_conn: db_conn.close()

        curtime = time.strftime('%Y-%m-%d %X')  # get current time to know where to put items in the list.
        curhour = curtime[11:13]                # events in the current hour should go in the last index
        #print(curtime, curhour) # for debug

        for row in all_rows:        # add each event to the appropriate element in data series
            auth_time = row[1]
            hour = auth_time[11:13]
            offset = int(curhour) - int(hour)
            if offset >= 0:         # increment counter
                ycoord[23 - offset] += 1
            else:
                ycoord[0 - offset] += 1

        #print ycoord   #for debug
        report_fname = 'daily/' + curtime.replace(' ','_').replace(':','') + '-last24.html'

        # generate plotly file
        plotly.offline.plot({
            "data": [Scatter(x=xcoord, y=ycoord)],
            "layout": Layout(title="Honeypot Trends - Last 24 Hours", xaxis=dict(title='Hour'),
                             yaxis=dict(title='Brute-Force Authentication Attempts'))
        }, auto_open=False, filename=report_fname)

        time.sleep(86400)   # sleep 1 day and then loop again

# initializes program; reads in configuration file and starts services with appropriate parameters
# returns config file object
def start_honeypot():
    Config = ConfigParser.ConfigParser()    # initialize configparser
    Config.read('honeypot.cfg')             # read in config file
    # start webserver thread
    thread.start_new_thread(handle_webserver,(('0.0.0.0', int(Config.get('web_srv', 'port'))), Config))
    # start log interactions thread
    thread.start_new_thread(log_interactions,())
    # start daily trend report generator
    thread.start_new_thread(daily_trends_report, ())
    # start telnet
    handle_telnet(('0.0.0.0', int(Config.get('telnet_srv', 'port'))), Config)   # initializes telnet server
    return Config


def main():
    try:
        start_honeypot()        # startup honeypot
    except KeyboardInterrupt:
        global EXITAPP
        EXITAPP = True
        sys.exit()              # gracefully end when interrupt is received


if __name__ == "__main__":
    main()