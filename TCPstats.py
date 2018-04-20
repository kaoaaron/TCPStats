import dpkt
import socket
import datetime
import sys
from collections import OrderedDict

if(len(sys.argv) != 2):
    print "Invalid Parameters. Please make sure to enter exactly 1 input argument.\n"
    sys.exit()

f = open(sys.argv[1], 'rb')
pcap = dpkt.pcap.Reader(f)

res_count = 0;

packets = []
unique = []
packetcount = 0

#loops through cap file and store data in list
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    
    #gather info to store in tuple
    source_ip = socket.inet_ntoa(ip.src)
    dest_ip = socket.inet_ntoa(ip.dst)
    source_port = tcp.sport
    dest_port = tcp.dport
    timestamp = ts
    syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
    res_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
    fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
    dataBytes = len(tcp.data)
    seqNum = tcp.seq
    ackNum = tcp.ack
    wsize = tcp.win
    
    packets.append([source_ip,dest_ip,source_port,dest_port,timestamp,syn_flag,res_flag,fin_flag, dataBytes, seqNum, ackNum, wsize])
    unique.append([source_ip,dest_ip,source_port,dest_port])

strunique = []
pcount = len(unique)

#appends unique code to each packet to determine unique connections
for x in range(0, pcount):
    if(unique[x][2] > unique[x][3] or unique[x][2] == unique[x][3]):
        strunique.append(unique[x][0] + unique[x][1] + str(unique[x][2]) + str(unique[x][3]))
    elif(unique[x][2] < unique[x][3]):
        strunique.append(unique[x][1] + unique[x][0] + str(unique[x][3]) + str(unique[x][2]))
    packets[x].append(strunique[x])
   
#strunique = set(strunique) this makes the connections unordered and hard for TA to mark

strunique = list(OrderedDict.fromkeys(strunique))

completeconnections = 0

print "A) Total TCP Connections:", len(strunique), "\n"

print "B) Connections' Details"

durations = []
totalpackets = []
RTT = []
cWinsize = []
resConnections = 0
resConCount = 0
noFins = 0
conNum = 0

#for each unique connection
for x in strunique:
    synCount = 0
    resCount = 0
    finCount = 0
    firstSynTime = 0
    lastFinTime = 0
    port1 = 0
    port2 = 0
    dir1 = 0
    dir2 = 0
    datadir1 = 0
    datadir2 = 0
    ip1 = "No IP Specified"
    ip2 = ip1
    synFlag = False
    resFlag = False
    ipFlag = False
    resFlag = False
    lookup = {}
    #loop through packets list
    for y in range(0, pcount):
        #if packet in list is part of same TCP connection specified in x
        if(x == packets[y][12]):
            
            #gets ips and ports
            if(ipFlag == False):
                ipFlag = True
                ip1 = packets[y][0]
                ip2 = packets[y][1]
                port1 = packets[y][2]
                port2 = packets[y][3]
            #direction flow 1
            if(packets[y][0] == ip1):
                dir1 = dir1 + 1
                datadir1 = datadir1 + packets[y][8]
            #direction flow 2
            elif(packets[y][0] == ip2):
                dir2 = dir2 + 1
                datadir2 = datadir2 + packets[y][8]
            #check for syn res and fin flags
            if(packets[y][5] == True):
                if(synFlag == False):
                    synFlag = True
                    firstSynTime = packets[y][4]  
                synCount = synCount + 1
            if(packets[y][6] == True):
                resCount = resCount + 1
            if(packets[y][7] == True):
                lastFinTime = packets[y][4]
                finCount = finCount + 1
    conNum = conNum + 1
    #finds total reset TCP connections     
    if(resCount >= 1):
        resConCount = resConCount + 1
    #finds number of open connections
    if(finCount == 0):
        noFins = noFins + 1
    #if at least 1 syn and 1 fin, complete connection specified
    if(synCount >= 1 and finCount >= 1):
        for y in range(0, pcount):
            if(x == packets[y][12]):
                cWinsize.append(packets[y][11])
                           
                #if packet in list is part of same TCP connection specified in x
            if(x == packets[y][12]):
                lookup[packets[y][4]] = packets[y][9] + packets[y][8]
                #calculate RTT
                if(packets[y][10] in lookup.values()):
                    for key, val in lookup.iteritems():
                        if val == packets[y][10]:
                            RTT.append(packets[y][4] - key)
                            #print(packets[y][4] - key)
                            lookup[key] = ""
        
        
        completeconnections = completeconnections + 1
        print "====================================="
        print "Connection #", conNum
        if(resCount == 0):
            print "S", synCount, "F", finCount
        else:
            print "S",synCount,"F",finCount,"/ R"
            if(resFlag == False):
                resFlag = True
                resConnections = resConnections + 1
            
        duration = lastFinTime-firstSynTime
        durations.append(duration)
        print 'Source Address:', ip1
        print 'Destination Address:', ip2
        print 'Source Port:', port1
        print 'Destination Port:', port2
        print 'Start Time: ', str(datetime.datetime.utcfromtimestamp(firstSynTime))
        print 'End Time: ', str(datetime.datetime.utcfromtimestamp(lastFinTime))
        print 'Duration: ', duration, 'seconds'
        print ip1,'Port:', port1, '-->', ip2, 'Port:', port2, '(packet count:', dir1, ',data bytes:', datadir1, ")"
        print ip2,'Port:', port2,'-->', ip1, 'Port:', port2,'(packet count:', dir2, ',data bytes', datadir2, ")"
        print 'Total Packets:', dir1+dir2
        print 'Total Data Bytes:', datadir1+datadir2 
        
        totalpackets.append(dir1+dir2)
    #if not complete connection print stats
    else: 
        print "====================================="
        print "Connection #", conNum
        print "***CONNECTION NOT COMPLETE***"
	if(resCount == 0):
            print "S", synCount, "F", finCount
        else:
            print "S",synCount,"F",finCount,"/ R"
            if(resFlag == False):
                resFlag = True
                resConnections = resConnections + 1
        print 'Source Address:', ip1
        print 'Destination Address:', ip2
        print 'Source Port:', port1
        print 'Destination Port:', port2
        print 'Start Time: ', str(datetime.datetime.utcfromtimestamp(firstSynTime))
        print 'End Time: ', str(datetime.datetime.utcfromtimestamp(lastFinTime))
        print 'Duration: ', duration, 'seconds'
        print ip1,'Port:', port1, '-->', ip2, 'Port:', port2, '(packet count:', dir1, ',data bytes:', datadir1, ")"
        print ip2,'Port:', port2,'-->', ip1, 'Port:', port2,'(packet count:', dir2, ',data bytes', datadir2, ")"
        print 'Total Packets:', dir1+dir2
        print 'Total Data Bytes:', datadir1+datadir2 
        
print "=====================================\n"
print "C) General"
print "Total Complete Connections:", completeconnections
print "Total Reset TCP Connections:", resConCount
print "Total # of Still Open TCP Connections:", noFins

print "\nD) Complete TCP Connections"
print "Total Reset TCP Complete Connections:", resConnections
print "\n"
print "Min Complete Connection Duration:", min(durations), "seconds"
print "Max Complete Connection Duration:", max(durations), "seconds"
print "Mean Complete Connection Duration:", float(sum(durations))/max(len(durations), 1), "seconds"
print "\n"
print "RTT min:", min(RTT), "seconds"
print "RTT max:", max(RTT), "seconds"
print "RTT mean:", float(sum(RTT))/max(len(RTT), 1), "seconds"
print "\n"
print "Min Packet Count in Complete Connection:", min(totalpackets)
print "Max Packet Count in Complete Connection", max(totalpackets)
print "Mean Total Packet Count in Complete Connection:", float(sum(totalpackets))/max(len(totalpackets), 1)
print "\n"
print "Min Receive Window Size:", min(cWinsize), "bytes"
print "Max Receive Window Size:", max(cWinsize), "bytes"
print "Mean Receive Window Size:", float(sum(cWinsize))/max(len(cWinsize), 1), "bytes"
