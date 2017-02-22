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
#include "tcp.h"

using std::cout;
using std::endl;
using std::cerr;
using std::string;
using std::queue;


Packet WritePacket(const Connection c, const unsigned int &id, const unsigned char &hlen, const unsigned int &acknum, unsigned int &seq, unsigned short &window, unsigned short &urgentpointer, unsigned char &flags, const char *data, unsigned short datalen){

 // MakePacket constructs a packet, takes everything that goes into a packet as params.

	Packet p(data, datalen);
	IPHeader iph;
	TCPHeader tcph;

	//Construct IP-Layer Header
	iph.SetProtocol(IP_PROTO_TCP);
	iph.SetSourceIP(c.src);
	iph.SetDestIP(c.dest);
	iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH + datalen);
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
  srand(time(NULL));
  MinetHandle mux, sock;

  ConnectionList<TCPState> connection_list;
  //queue<SockRequestResponse> sock_queue;  

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
  double min_timeout = -1;

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

	unsigned short window = 0;
	unsigned short &windowp = window;

	unsigned int checksum = 0;
	unsigned int &checksump = checksum;

	unsigned short urgentpointer = 0;
	unsigned short &urgentpointerp = urgentpointer;

	unsigned int options = 0;
	unsigned int &optionsp = options;

	unsigned int padding = 0;
	unsigned int &paddingp = padding;

	Buffer data;
	Buffer &datap = data;

	unsigned char orgflags= 0;
	unsigned char &orgflagsp = orgflags;

	unsigned char newflags= 0;
	unsigned char &newflagsp = newflags;

	unsigned char hlen= 5;
	unsigned char &hlenp = hlen;

  while (MinetGetNextEvent(event, min_timeout)==0) {
	newflags = 0;
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
        unsigned iphlen =IPHeader::EstimateIPHeaderLength(p);
	cerr << "estimated header len="<<tcphlen<<"\n";
        p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);

        IPHeader ipl=p.FindHeader(Headers::IPHeader);
	Connection c;
	ipl.GetDestIP(c.src);
	ipl.GetSourceIP(c.dest);

        TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
	tcph.GetDestPort(c.srcport);
	tcph.GetSourcePort(c.destport);
	tcph.GetAckNum(seqp);
	tcph.GetSeqNum(acknump);
	tcph.GetFlags(orgflagsp);
	tcph.GetWinSize(windowp);	

	cerr << "TCP Packet rcvd: IP Header is "<<ipl<<" and ";
        cerr << "TCP Header is "<<tcph << " and ";

        cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
	checksumok = tcph.IsCorrectChecksum(p);

	if (seq == 0) { 
		seq = rand() % 50000;
	}
	c.protocol = IP_PROTO_TCP;

	ConnectionList<TCPState>::iterator cs = connection_list.FindMatching(c);
		if (cs == connection_list.end()){
			//c.dest = IPAddress(IP_ADDRESS_ANY);
			//c.destport = PORT_ANY;
			cerr << "Not listening for: " << c << endl << endl;
		}
		if ((*cs).connection.dest == IPAddress(IP_ADDRESS_ANY) || (*cs).connection.destport == PORT_ANY) {
			(*cs).connection.dest = c.dest;
			(*cs).connection.src = c.src;
			(*cs).connection.srcport = c.srcport;
			cerr << c.dest << endl;
			(*cs).connection.destport = c.destport;
			(*cs).state.SetState(LISTEN);
		}
		
		
	cerr << "Entering switch phase" << endl; 
	switch ((*cs).state.GetState()) {
		case CLOSED:
			cerr << "In closed phase" << endl; 
			break;
			
		case LISTEN:
			cerr << "Entering listen phase" << endl; 
			if (IS_SYN(orgflags) && !IS_ACK(orgflags) || IS_RST(orgflags)) {
				//Passive open 
				(*cs).state.SetLastSent(seq);
				(*cs).state.SetSendRwnd(window);
				
				(*cs).state.SetState(SYN_RCVD);
				SET_SYN(newflags);
				SET_ACK(newflags);
				
				Packet respPacket = WritePacket(c, idp, hlenp, acknum + 1, seqp, windowp, urgentpointerp, newflagsp, "", 0); 
				MinetSend(mux, respPacket);
        			TCPHeader tcprh=respPacket.FindHeader(Headers::TCPHeader);
        			IPHeader iprh=respPacket.FindHeader(Headers::IPHeader);
				cerr << "IP response head: " << iprh << endl;
				cerr << "TCP response head: " << tcprh << endl;

				(*cs).state.SetLastRecvd(acknum + 1);
			}
			break;
		case SYN_SENT:
			if(IS_SYN(orgflags) && IS_ACK(orgflags)) {
				cerr << "ACTIVE OPEN!" << endl;
				(*cs).state.SetState(ESTABLISHED);
				SET_ACK(newflags);
				Packet respPacket = WritePacket(c, idp, hlenp, acknum + 1, seqp, windowp, urgentpointerp, newflagsp, "", 0); 
				MinetSend(mux, respPacket);
				SockRequestResponse write(WRITE, (*cs).connection, data, 0, EOK);
				write.type = WRITE;
				(*cs).state.SetLastRecvd(acknum + 1);
			} else if(IS_SYN(orgflags)) {
				// Handle a possible passive open?
			}
			break;
		case SYN_RCVD:
			cerr << "In SYN_RCVD phase" << endl;
			//cerr << ((*cs).state.GetLastRecvd()) << endl;
			//cerr << seq << endl;
			//if ((*cs).state.GetLastRecvd() == acknum+1){
				cerr << "entered outer if" << endl;
				if (IS_ACK(orgflags)){
					cerr << "Established" << endl;
					(*cs).state.SetState(ESTABLISHED);
					//(*cs).state.SetSendRwnd(windowp);
					//(*cs).state.SetLastAcked((*cs).state.GetLastAcked()+1);
					//(*cs).bTmrActive = false;
					
				} else if ((IS_SYN(orgflags) && !IS_ACK(orgflags) || IS_RST(orgflags))){
					// DEALING WITH LOST PACKET 
					cerr << "SYN ACK LOST" << endl;
					(*cs).state.SetLastSent(seq);
					(*cs).state.SetSendRwnd(window);

					SET_SYN(newflags);
					SET_ACK(newflags);
					Packet respPacket = WritePacket(c, idp, hlenp, acknum + 1, seqp, windowp, urgentpointerp, newflagsp, "", 0); 
					MinetSend(mux, respPacket);
					(*cs).state.SetLastRecvd(acknum + 1);
				}
			//}
			break;
		case ESTABLISHED:
			cerr << "In established phase" << endl;
			if(IS_FIN(orgflags)) {
				cerr << "Finito" << endl;
				unsigned short tempdatalen = 0;
				unsigned short &tempdatalenp = tempdatalen;
				unsigned char tempheaderlen = 0;
				unsigned char &tempheaderlenp = tempheaderlen;
	
				ipl.GetTotalLength(tempdatalenp);
				ipl.GetHeaderLength(tempheaderlenp);

				tempdatalen -= 4 * tempheaderlen + tcphlen;
				
				data = p.GetPayload().ExtractFront(tempdatalen);
				cerr << data << endl;


				(*cs).state.SetState(CLOSE_WAIT);
				SET_ACK(newflags);
				Packet respPacket = WritePacket(c, idp, hlenp, acknum + 1, seqp, windowp, urgentpointerp, newflagsp, "", 0); 
				MinetSend(mux, respPacket);
				(*cs).state.SetLastRecvd(acknum + 1);
				(*cs).connection.protocol = IP_PROTO_TCP;
				SockRequestResponse close(WRITE, (*cs).connection, data, tempdatalen, EOK);
				cerr << close << endl;
				MinetSend(sock, close);
			}
			else if(IS_RST(orgflags)) {
				cerr << "Reset" << endl;
				/*(*cs).state.SetLastSent(seq);
				(*cs).state.SetSendRwnd(window);
				SET_SYN(newflags);
				SET_ACK(newflags);
				Packet respPacket = WritePacket(c, idp, hlenp, acknum + 1, seqp, windowp, urgentpointerp, newflagsp, "", 0); 
				MinetSend(mux, respPacket);*/
			}
			else {
				cerr << "we have data packet" << endl;
				unsigned short tempdatalen = 0;
				unsigned short &tempdatalenp = tempdatalen;
				unsigned char tempheaderlen = 0;
				unsigned char &tempheaderlenp = tempheaderlen;
	
				ipl.GetTotalLength(tempdatalenp);
				ipl.GetHeaderLength(tempheaderlenp);

				tempdatalen -= 4 * tempheaderlen + tcphlen;
				
				data = p.GetPayload().ExtractFront(tempdatalen);
				cerr << data << endl;
				
				(*cs).connection.protocol = IP_PROTO_TCP;
				SockRequestResponse write(WRITE, (*cs).connection, data, tempdatalen, EOK);
				MinetSend(sock, write);
				SET_ACK(newflags);	
				Packet respPacket = WritePacket(c, idp, hlenp, acknum + tempdatalen, seqp, windowp, urgentpointerp, newflagsp, "", 0); 
				MinetSend(mux, respPacket);
				(*cs).state.SetLastRecvd(acknum + tempdatalen);
			}
			break;
	
	case FIN_WAIT1:
		if (IS_FIN(orgflags) && IS_ACK(orgflags)){
			cerr << "Received FIN and ACK" << endl;
			(*cs).state.SetState(TIME_WAIT);
			(*cs).state.SetLastAcked(acknum);
			(*cs).state.SetLastRecvd(seq);
			Packet respPacket = WritePacket(c, idp, hlenp, acknum + 1, seqp, windowp, urgentpointerp, newflagsp, "", 0); 
			MinetSend(mux, respPacket);
		}	else if (IS_FIN(orgflags)){
			cerr << "Received FIN" << endl;
			(*cs).state.SetState(CLOSING);
			SET_ACK(newflags);		
			Packet respPacket = WritePacket(c, idp, hlenp, acknum + 1, seqp, windowp, urgentpointerp, newflagsp, "", 0); 
			MinetSend(mux, respPacket);
			(*cs).state.SetLastRecvd(acknum + 1);
		} else if (IS_ACK(orgflags) && !IS_PSH(orgflags)){
			cerr << "Received Close ACK" << endl;
			(*cs).state.SetState(FIN_WAIT2);
			(*cs).state.SetLastRecvd(acknum + 1);
		}
		break;

	case FIN_WAIT2:
		if (IS_FIN(orgflags)){
			cerr << "Received FIN" << endl;
			(*cs).state.SetState(TIME_WAIT);
			SET_ACK(newflags);
			Packet respPacket = WritePacket(c, idp, hlenp, acknum + 1, seqp, windowp, urgentpointerp, newflagsp, "", 0); 
			MinetSend(mux, respPacket);
		}
		break;
	case CLOSING:
		cerr << "CLOSING!!!" << endl;
		if (IS_ACK(orgflags)){
			(*cs).state.SetState(TIME_WAIT);
			(*cs).state.SetLastRecvd(seq);
			(*cs).state.SetLastAcked(acknum);
		}
		break;
	case TIME_WAIT:
		cerr << "YAYYY TIME WAIT" << endl;
		sleep(2*MSL_TIME_SECS);
		(*cs).state.SetState(CLOSE);
		break;
	case LAST_ACK:
		cerr << "LAST ACK BEFORE CLOSING." << endl;
		if (IS_ACK(orgflags)){
			connection_list.erase(cs);
			(*cs).state.SetState(CLOSED);
		}		
	
      }
      }


      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        cerr << "Received Socket Request in event=sock:" << s << endl;
	ConnectionList<TCPState>::iterator cs = connection_list.FindMatching(s.connection);

	/*
	ConnectionToStateMapping<TCPState> map;
	if (cs == clist.end()) {
		map.connection = s.connection;
		map.state.SetState(CLOSED);
		connection_list.push
	*/

	switch (s.type){
		case CONNECT:
			cerr << "Connect request from application layer";
			break;
		case ACCEPT:
			break;
		case WRITE:
			cerr << "In write" << endl;
			break;
		case CLOSE:
			cerr << "In close" << endl;
			switch ((*cs).state.GetState()){
				case SYN_SENT:
					break;
				case SYN_RCVD:
					break;
				case ESTABLISHED:
					break;
				case CLOSE_WAIT:
					cerr << "In close wait" << endl;
					(*cs).state.SetState(LAST_ACK);
					(*cs).state.SetLastSent((*cs).state.GetLastSent()+1);
					(*cs).state.SetLastRecvd((*cs).state.GetLastRecvd());
					SET_FIN(newflags);
					Packet respP = WritePacket(s.connection, idp, hlenp, acknum, seqp, windowp, urgentpointerp, newflagsp, "", 0); 
					cerr << "RESPONDED WITH: " << respP;
					MinetSend(mux, respP);
					break;
			}
		break;
	}		
	
      }
      if(event.eventtype == MinetEvent::Timeout) {
		cerr << "TIMEOUT" << endl;
		ConnectionList<TCPState>::iterator i=connection_list.begin();
		for(; i!=connection_list.end();++i) {
			if((*i).bTmrActive) {
				cerr<<*i<<endl;
			}
		}
		if((*connection_list.FindEarliest()).Matches((*connection_list.end()).connection)) 
			min_timeout = -1;
		else
			min_timeout = (*connection_list.FindEarliest()).timeout;
      }
    }
  }
  return 0;
}
