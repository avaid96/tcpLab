#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <iostream>
#include <queue>

#include "Minet.h"
#include "tcpstate.h"

using std::cout;
using std::endl;
using std::cerr;
using std::string;


Packet WritePacket(const Connection c, const unsigned int &id, const unsigned char &hlen, const unsigned int &acknum, unsigned int &seq, unsigned int &dataoffset, unsigned int &reserved, unsigned int &window, unsigned int &urgentpointer, unsigned char &flags, const char *data, unsigned short datalen){

 // MakePacket constructs a packet, takes everything that goes into a packet as params.

	Packet p(data, datalen);
	IPHeader iph;
	TCPHeader tcph;

	//Construct IP-Layer Header
	iph.SetProtocol(IP_PROTO_TCP);
	iph.SetSourceIP(c.src);
	iph.SetDestIP(c.dest);
	iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
	iph.SetID(id);

	p.PushFrontHeader(iph);

	//Construct TCP-Layer Header
	tcph.SetDestPort(c.destport, p);
	tcph.SetSourcePort(c.srcport, p);
	tcph.SetSeqNum(seq, p);
	tcph.SetAckNum(acknum, p);
	tcph.SetWinSize(window, p);
	tcph.SetHeaderLen(hlen, p);
	tcph.SetUrgentPtr(urgentpointer, p);
	tcph.SetFlags(flags, p);

	p.PushBackHeader(tcph);

	return p;
}

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;

  ConnectionList<TCPState> connection_list;
  //queue<SockRequestResponse> sock_response;  

  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;

  //Buffer datagram;
  //Buffer &data = datagram;

	//Dunno
	unsigned char oldflags;

	//For use in IP Header
	unsigned int id = 0;
	unsigned int idp = id;

	//For use in TCP Header
	unsigned int sourceport = 0;
	unsigned int &sourceportp = sourceport;

	unsigned int destport = 0;
	unsigned int &destportp = destport;

	unsigned int acknum = 0;
	unsigned int &acknump = acknum;

	unsigned int seq = 0;
	unsigned int &seqp = seq;

	unsigned int dataoffset = 0;
	unsigned int &dataoffsetp = dataoffset;

	unsigned int reserved = 0;
	unsigned int &reservedp = reserved;

	unsigned int window = 0;
	unsigned int &windowp = window;

	unsigned int checksum = 0;
	unsigned int &checksump = checksum;

	unsigned int urgentpointer = 0;
	unsigned int &urgentpointerp = urgentpointer;

	unsigned int options = 0;
	unsigned int &optionsp = options;

	unsigned int padding = 0;
	unsigned int &paddingp = padding;

	unsigned int data = 0;
	unsigned int &datap = data;

  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      cerr << "invalid event from Minet" << endl;
      //  Data from the IP layer below  //
      if (event.handle==mux) {
        bool checksumok;
	unsigned short len;
	Packet p;
        MinetReceive(mux,p);
        unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
        cerr << "estimated header len="<<tcphlen<<"\n";
        p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
 	


        IPHeader ipl=p.FindHeader(Headers::IPHeader);
	Connection c;
	ipl.GetDestIP(c.src);
	ipl.GetSourceIP(c.dest);
	ipl.GetProtocol(c.protocol);
	

        TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
	tcph.GetDestPort(c.srcport);
	tcph.GetSourcePort(c.destport);
	tcph.GetAckNum(acknum);
	tcph.GetSeqNum(seq);
	//tcph.GetWinSize(window);	
	checksumok = tcph.IsCorrectChecksum(p);

	//TODO: Something about seqnum being nonzero

	ConnectionList<TCPState>::iterator cs = connection_list.FindMatching(c);
	/*
	if (cs != connection_list.end()){
		SockRequestResponse write(WRITE, (*cs).connection, data, len, EOK);
	
		if (!checksumok){
			MinetSendToMonitor(MinetMonitoringEvent("forwarding packet to sock even though checksum failed"));}
		MinetSend(sock, write);
	} else {
	MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
	IPAddress source; ipl.GetSourceIP(source);
	ICMPPacket error(source, DESTINATION_UNREACHABLE, PORT_UNREACHABLE, p);
	MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
	MinetSend(mux, error);
	}
	*/

		
        cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
        cerr << "TCP Header is "<<tcph << " and ";

        cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
      }
          //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        cerr << "Received Socket Request:" << s << endl;
      }
    }
  }
  return 0;
}
