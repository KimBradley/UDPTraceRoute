/* 
 * Kim Bradley
 * 4/24/2013
 * CSCI 4760
 * Perdisci
 * 
 * UDPTraceroute.java
 */

import org.savarese.vserv.tcpip.*;
import com.savarese.rocksaw.net.RawSocket;

import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.net.SocketException;
import java.net.NetworkInterface;

import java.util.Collections;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;

import java.io.InterruptedIOException;
import java.text.DecimalFormat;
import java.lang.Math;

/* 
 * UDPTraceroute takes a destination port, number of hops, and and IP address and traces
 * the route for the number of hops.
 * 
 * To Run: (VM root access in build folder)
 * java -Djava.library.path=../lib/ -cp ./:../lib/* UDPTraceroute -p <port> -h <max_hops>  <IP address>
 */
public class UDPTraceroute {
    
    final static String HARDCODED_VM_ADDRESS = "172.17.152.97";
    final static int TIMEOUT = 5000; // 5 seconds
    final static byte[] PAYLOAD = "CSCI4760 Kim Bradley".getBytes(); // data to send
    
    static String srcAddr, time, dest_address;
    static int TTL, UDP_dest_port, max_hops;
    static long start, end;
    static byte[] sendData;
    static InetAddress INET_address;
    static RawSocket socket, rcv_socket;
    
    public static void main(String[] args) throws UnknownHostException {
	
	/* Set defaults (all expected to change) */
	srcAddr = "UNKNOWN";
	UDP_dest_port = 1234;
	max_hops = 10;
	dest_address = HARDCODED_VM_ADDRESS;
	
	int numArgs = args.length;
	
	/* Set user-given args to proper parameters */
	for (int i=0; i<numArgs-1; i++) {
	    if (args[i].equals("-p"))
		UDP_dest_port = Integer.parseInt(args[i+1]);
	    else if (args[i].equals("-h")) {
		max_hops = Integer.parseInt(args[i+1]);
		dest_address = args[i+2];
	    }
	}
	
	INET_address = InetAddress.getByName(dest_address);
	
	//System.out.println("UDP_dest_port: " + UDP_dest_port);
	//System.out.println("max_hops: " + max_hops);
	//System.out.println("dest_address: " + dest_address);
	System.out.println("\n***********************START_TRACEROUTE***********************");
	
	try {
	    /* Create sockets for sending and receiving */
	    socket = new RawSocket();
	    rcv_socket = new RawSocket();
	    
	    TTL = 1; // always start at 1st hop
	    
	    /* Loop until max_hops or dest_address are reached */
	    while ((TTL <= max_hops) && (!srcAddr.equals(dest_address))) {
	    	try {
		    sendPacket(socket);
		    socket.close();
		    receivePacket(rcv_socket);
		    rcv_socket.close();
		    
		    /* Set time to print out in milliseconds to two decimal places */
		    double milliTime = (end-start)/ (double)1000000;
		    time = (new DecimalFormat("##.##").format(milliTime)) + "ms";
		    
	    	}
	    	/* If InterruptedIOException is thrown, hop timed out */
	    	catch (InterruptedIOException e) {
		    time = "(timeout)";
		    rcv_socket.close();
		}
		System.out.println("TTL=" + TTL + "\t|\tHopIP=" + srcAddr + "\t|\tTime=" + time);
		TTL++;
	    }
	}
	catch (Exception e) {
	    System.out.println("\nTry in main().\n");
	    e.printStackTrace();
	}
	
	System.out.println("************************STOP_TRACEROUTE***********************\n");
    }// end main() method
    
    
    
    /* Method to create and send packet to socket */
    static void sendPacket(RawSocket socket) throws Exception {
	try {	    	
	    time = ""; // reset time for each hop
	    
	    /* Set size of UDPPacket to sizes of PAYLOAD + IP (20bytes) + UDP (8bytes) */
	    UDPPacket sendPacket = new UDPPacket(PAYLOAD.length + 28);
	    
	    /* IP Header */
	    sendPacket.setIPVersion(4);
	    sendPacket.setIPHeaderLength(5); // IP header is 5bytes because we specify no options
	    sendPacket.setIPPacketLength(20); // IP packet is 20bytes
	    sendPacket.setProtocol(IPPacket.PROTOCOL_UDP);
	    
	    sendPacket.setTTL(TTL);
	    
	    /* Both set destination and set source methods take a 32bit int rep of IP address */
	    sendPacket.setDestinationAsWord(intRep(INET_address)); 
	    sendPacket.setSourceAsWord(intRep(getLocalIP()));
	    
	    /* UDP Header */
	    sendPacket.setDestinationPort(UDP_dest_port);
	    sendPacket.setUDPDataByteLength(PAYLOAD.length);
	    sendPacket.setUDPPacketLength(PAYLOAD.length + 8); // UDP header is 8bytes
	    
	    byte[] buffer = new byte[sendPacket.size()];
	    
	    /* 
	     * Store current sendPacket data in buffer, add PAYLOAD to buffer by using System.arraycopy
	     * to copy the PAYLOAD after the header bytes (which are 28 bytes long), then set sendPacket
	     * data back to the modified buffer
	     */
	    sendPacket.getData(buffer);
	    System.arraycopy(PAYLOAD, 0, buffer, 28, PAYLOAD.length);			
	    sendPacket.setData(buffer);
	    
	    sendPacket.computeIPChecksum();
	    sendPacket.computeUDPChecksum();
	    
	    socket.open(RawSocket.PF_INET, RawSocket.getProtocolByName("udp"));
	    socket.setIPHeaderInclude(true);
	    
	    start = System.nanoTime(); // start time
	    socket.write(INET_address, buffer);
	}
	catch (Exception e) {
	    System.out.println("\nTry in sendPacket().\n");
	    e.printStackTrace();
	}
    }// end sendPacket() method
    
    
    
    /* Method to receive packet from receive socket */
    static void receivePacket(RawSocket rcv_socket) throws Exception {
	try {
	    rcv_socket.open(RawSocket.PF_INET, RawSocket.getProtocolByName("icmp"));
	    rcv_socket.setReceiveTimeout(TIMEOUT);
	    
	    byte[] buffer = new byte[rcv_socket.getReceiveBufferSize()];
	    ICMPPacket rcvPacket = new ICMPEchoPacket(buffer.length);
	    
	    rcv_socket.read(buffer);
	    end = System.nanoTime(); // end time
	    
	    rcvPacket.setData(buffer);
	    srcAddr = rcvPacket.getSourceAsInetAddress().getHostAddress();
	}
	catch (SocketException e) {
	    System.out.println("\nTry in receivePacket().\n");
	    e.printStackTrace();
	}
    }// end receivePacket() method
    
    
    
    /* Method to get local IP address (this code was provided) */
    static InetAddress getLocalIP() throws UnknownHostException {
	try {
	    Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
	    for (NetworkInterface netint : Collections.list(nets)) {
		if (netint.getName().equals("eth0")) {
		    Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
		    for (InetAddress inetAddress : Collections.list(inetAddresses)) {
			// look only for ipv4 addresses
			if (inetAddress instanceof Inet6Address)
			    continue;
			return inetAddress;
		    }
		}
	    }
	}
	catch (SocketException e) { e.printStackTrace(); }
	catch (Exception e) { e.printStackTrace(); }
	
	// Hopefully we don't get here
	System.out.println("\nWARNING: Using hardcoded IP specified at beginning of code.\n");
	return InetAddress.getByName(HARDCODED_VM_ADDRESS);
    }// end getLocalIP() method
    
    
    
    /* Method to convert an InetAddress to it's integer representation */
    static int intRep(InetAddress addr) {
	String[] str = addr.getHostAddress().split("\\.");
	int rtrn = Integer.parseInt(str[0]) * (int)Math.pow(2,24) + 
	    Integer.parseInt(str[1]) * (int)Math.pow(2,16) +
	    Integer.parseInt(str[2]) * (int)Math.pow(2,8) +
	    Integer.parseInt(str[3]);
	return rtrn;
    }// end inRep() method
    
}// end UDPTraceroute class



/*
 * SAMPLE OUTPUT:
 * 
 * [root@vm97 build]# java -Djava.library.path=../lib/ -cp ./:../lib/* UDPTraceroute -p 33434 -h 30  173.194.37.51
 * 
 * ***********************START_TRACEROUTE***********************
 * TTL=1	|	HopIP=172.17.152.1	|	Time=1.28ms
 * TTL=2	|	HopIP=128.192.0.5	|	Time=1.46ms
 * TTL=3	|	HopIP=128.192.254.49	|	Time=1.59ms
 * TTL=4	|	HopIP=128.192.254.49	|	Time=(timeout)
 * TTL=5	|	HopIP=128.192.166.33	|	Time=4.38ms
 * TTL=6	|	HopIP=74.125.48.33	|	Time=3.12ms
 * TTL=7	|	HopIP=64.233.174.2	|	Time=4.37ms
 * TTL=8	|	HopIP=64.233.175.92	|	Time=4.88ms
 * TTL=9	|	HopIP=173.194.37.51	|	Time=4.66ms
 * ************************STOP_TRACEROUTE***********************
 * 
 */