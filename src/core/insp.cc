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
#include <algorithm>

#include "Minet.h"
#include "tcpstate.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;
using std::cin;
using std::min;
using std::max;


//          ~~~~~ MACROS ~~~~~

#define TMR_TRIES 5
#define MSS 536
#define MAX_INFLIGHT MSS*8
#define RTT 3


#define SEND_BUF_SIZE(state) (state.TCP_BUFFER_SIZE - state.SendBuffer.GetSize())


//           ~~~~~ HELPERS ~~~~~
Packet MakePacket(Buffer data, Connection conn, unsigned int seq_n, unsigned int ack_n, size_t win_size, unsigned char flag);
void sendWithFlowControl(ConnectionList<TCPState>::iterator cxn, MinetHandle mux);
void SendPacket(MinetHandle handle, Buffer data, Connection conn, unsigned int seq_n, unsigned int ack_n, size_t win_size, unsigned char flag);
Packet ReceivePacket(MinetHandle handle); 

//          ~~~~~ MAIN ~~~~~                

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;
  srand(time(0)); // generate a random number 
  ConnectionList<TCPState> connectionsList;

  MinetInit(MINET_TCP_MODULE);

  mux = MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux == MINET_NOHANDLE) 
  {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock == MINET_NOHANDLE) 
  {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;

  while (MinetGetNextEvent(event, 10) == 0)
  {

    if (event.eventtype == MinetEvent::Timeout)
    {
      //loop through all the connections in the connections list
      for (ConnectionList<TCPState>::iterator cxn = connectionsList.begin(); cxn != connectionsList.end(); cxn++)
      {
        //if connection is closed, erase it from the connections list
        if (cxn->state.GetState() == CLOSED)
        {
          connectionsList.erase(cxn);
        }

        // check for active timers
        Time curr_time = Time();
        if (cxn->bTmrActive == true && cxn->timeout < curr_time)
        {
          // if there are no more timer tries for this state
          if (cxn->state.ExpireTimerTries()) //true if no more timer tries
          {
            //closes connection if the number of time outs reaches a threshold
            SockRequestResponse res;
            res.type = CLOSE;
            res.connection = cxn->connection;
            res.error = EOK;
            MinetSend(sock, res);
          }
          // else handle each case of timeout
          else
          {
            Packet sndPacket;
            unsigned char sendFlag;
            switch(cxn->state.GetState())
            {
              case SYN_RCVD:
              {
                cerr << "!!! TIMEOUT: SYN_RCVD STATE !!!  RE-SENDING SYN ACK !!!" << endl;
                SET_SYN(sendFlag);
                SET_ACK(sendFlag);
                SendPacket(mux, Buffer(NULL, 0), cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd(), cxn->state.GetRwnd(), sendFlag);
              }
              break;
              case SYN_SENT:
              {
                cerr << "!!! TIMEOUT: SYN_SENT STATE !!! RE-SENDING SYN!!!" << endl;
                SET_SYN(sendFlag);
                SendPacket(mux, Buffer(NULL, 0), cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd(), SEND_BUF_SIZE(cxn->state), sendFlag);
              } 
              break;
              case ESTABLISHED:
              {
                cerr << "!!! TIMEOUT: ESTABLISHED STATE !!! RE-SENDING DATA !!!" << endl;
                if (cxn->state.N > 0) // if there are still packets inflight during the timeout
                {
                  cerr << "!!! TIMEOUT: ESTABLISHED STATE !!! RE-SEND DATA USING GBN !!!" << endl;
                  sendWithFlowControl(cxn, mux); //resends data using flow control (go-back-n)
                }
                // otherwise just need to resend ACK
                else
                {
                  cerr << "!!! TIMEOUT: ESTABLISHED STATE !!! RE-SENDING ACK !!!" << endl;
                  SET_ACK(sendFlag);
                  SendPacket(mux, Buffer(NULL, 0), cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd() + 1, cxn->state.GetRwnd(), sendFlag);
                }
              }
              break;
              case CLOSE_WAIT:
              {
                cerr << "!!! TIMEOUT: CLOSE_WAIT STATE !!! RE-SENDING ACK !!!" << endl;
                SET_ACK(sendFlag);
                SendPacket(mux, Buffer(NULL, 0), cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd(), cxn->state.GetRwnd(), sendFlag);
              }
              break;
              case FIN_WAIT1:
              {
                cerr << "!!! TIMEOUT: FIN_WAIT1 STATE !!! RE-SENDING FIN !!!" << endl;
                SET_FIN(sendFlag);
                SendPacket(mux, Buffer(NULL, 0), cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd(), SEND_BUF_SIZE(cxn->state), sendFlag);
              }
              break;
              case CLOSING:
              {
                cerr << "!!! TIMEOUT: CLOSING STATE !!! RE-SENDING ACK !!!" << endl;
                SET_ACK(sendFlag);
                SendPacket(mux, Buffer(NULL, 0), cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd(), cxn->state.GetRwnd(), sendFlag);
              }
              break;
              case LAST_ACK:
              {
                cerr << "!!! TIMEOUT: LAST_ACK !!! RE-SENDING FIN !!!" << endl;
                SET_FIN(sendFlag);
                SET_ACK(sendFlag);
                SendPacket(mux, Buffer(NULL, 0), cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd(), SEND_BUF_SIZE(cxn->state), sendFlag);
              }
              break;
              case TIME_WAIT:
              {
                cerr << "!!! TIMEOUT: TIME_WAIT !!! RE-SENDING ACK !!!" << endl;
                SET_ACK(sendFlag);
                SendPacket(mux, Buffer(NULL, 0), cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd(), cxn->state.GetRwnd(), sendFlag);
              }
            }
            //set new timeout for cxn
            cxn->timeout = Time() + RTT;
          }
        }
      }
    }
    // Unexpected event type, just ignore
    else if (event.eventtype != MinetEvent::Dataflow || event.direction != MinetEvent::IN)
    {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    } 
    //  Data from below the IP layer
    else if (event.handle == mux) 
    {
      cerr << "\n~~~ START OF IP LAYER ~~~ \n";

      cerr << "  ~~~  PACKET RECEIVED FROM BELOW ~~~\n";

      Packet receivedPacket = ReceivePacket(mux);

      unsigned tcphlen = TCPHeader::EstimateTCPHeaderLength(receivedPacket);
      receivedPacket.ExtractHeaderFromPayload<TCPHeader>(tcphlen);

      IPHeader recIPheader = receivedPacket.FindHeader(Headers::IPHeader);
      TCPHeader recTCPheader = receivedPacket.FindHeader(Headers::TCPHeader);

      //for debugging purposes
      cerr << recIPheader <<"\n";
      cerr << recTCPheader << "\n";
      cerr << "Checksum is " << (recTCPheader.IsCorrectChecksum(receivedPacket) ? "VALID\n\n" : "INVALID\n\n");
      cerr << receivedPacket << "\n";

      // Unpack useful data
      Connection conn;
      recIPheader.GetDestIP(conn.src);
      recIPheader.GetSourceIP(conn.dest);
      recIPheader.GetProtocol(conn.protocol);
      recTCPheader.GetDestPort(conn.srcport);
      recTCPheader.GetSourcePort(conn.destport);

      unsigned short recWindow; 
      recTCPheader.GetWinSize(recWindow);

      unsigned int recSeqNum;
      unsigned int recAckNum;
      unsigned int sendAckNum;
      unsigned int sendSeqNum;
      recTCPheader.GetSeqNum(recSeqNum);
      recTCPheader.GetAckNum(recAckNum);
      // Since ack_n denotes the next packet expected
      sendAckNum = recSeqNum + 1;

      unsigned char receivedFlag;
      recTCPheader.GetFlags(receivedFlag);

      ConnectionList<TCPState>::iterator cxn = connectionsList.FindMatching(conn);
      if (cxn != connectionsList.end() && recTCPheader.IsCorrectChecksum(receivedPacket))
      {   
        recTCPheader.GetHeaderLen((unsigned char&)tcphlen); 
        tcphlen -= TCP_HEADER_MAX_LENGTH;
        Buffer data = receivedPacket.GetPayload().ExtractFront(tcphlen); // getting the contents as long as tcphlen from the payload
        data.Print(cerr); 
        cerr << endl;

        unsigned char sendFlag = 0; // SET_SYN function needs a parameter of type unsigned char which is then ORed with 10 (bitwise OR)
        SockRequestResponse res;
        Packet sndPacket;

        switch(cxn->state.GetState())
        {
          case CLOSED:
          {
            cerr << "\n   ~~~ MUX: CLOSED STATE ~~~\n";
          }
          break;
          case LISTEN:
          {
            cerr << "\n   ~~~ MUX: LISTEN STATE ~~~\n";
            // coming from ACCEPT in socket layer
            if (IS_SYN(receivedFlag))
            {
              sendSeqNum = rand(); // The sequence number for the packet sent back is randomly chosen
              

              cxn->state.SetState(SYN_RCVD);
              cxn->state.SetLastRecvd(recSeqNum);
              cxn->state.SetLastSent(sendSeqNum); 

              cxn->bTmrActive = true; // Set timer of cxn to active
              cxn->timeout = Time() + RTT; // To set the timeout interval to be that of 1 RTT starting the current time. This sets a timeout for receiving an ACK from remote side.
              SET_SYN(sendFlag);
              SET_ACK(sendFlag);
              SendPacket(mux, Buffer(NULL, 0), conn, sendSeqNum, sendAckNum, cxn->state.GetRwnd(), sendFlag);
            }
          }
          break;
          case SYN_RCVD:
          {
            cerr << "\n   ~~~ MUX: SYN_RCVD STATE ~~~\n";
            if (IS_ACK(receivedFlag)) {
              cerr << "Received packet is ACKED! Will try to establish connection!" << endl;
            }

            if (IS_ACK(receivedFlag) && cxn->state.GetLastSent() == recAckNum - 1)
            {
              cerr << "Connection is established!" << endl;
              cxn->state.SetState(ESTABLISHED);
              cxn->state.SetLastRecvd(recSeqNum - 1); // used to keep track of sequence numbers

              // timer
              cxn->bTmrActive = false;
              cxn->state.SetTimerTries(TMR_TRIES);

              // create res to send to sock
              res.type = WRITE;
              res.connection = conn;
              res.bytes = 0;
              res.error = EOK;
              MinetSend(sock, res);
            }
          }
          break;
          case SYN_SENT:
          {
            cerr << "\n   ~~~ MUX: SYN_SENT STATE ~~~\n";
            if (IS_SYN(receivedFlag) && IS_ACK(receivedFlag))
            {
              cerr << "Last Acked: " << cxn->state.GetLastAcked() << endl;
              cerr << "Last Sent: " << cxn->state.GetLastSent() << endl;
              cerr << "Last Recv: " << cxn->state.GetLastRecvd() << endl;
              sendSeqNum = cxn->state.GetLastSent() + data.GetSize() + 1;
              cerr << "increment" << data.GetSize() + 1;

              cxn->state.SetState(ESTABLISHED);
              cxn->state.SetLastAcked(recAckNum - 1);
              cxn->state.SetLastRecvd(recSeqNum); 


              SET_ACK(sendFlag);
              SendPacket(mux, Buffer(NULL, 0), conn, sendSeqNum, sendAckNum, SEND_BUF_SIZE(cxn->state), sendFlag);

              // ACKS have size 6 for some reason
              cxn->state.SetLastSent(max((int) cxn->state.GetLastSent() + 7, (int) sendSeqNum));

              res.type = WRITE;
              res.connection = conn;
              res.bytes = 0;
              res.error = EOK;
              MinetSend(sock, res);
            }
          }
          break;
          case SYN_SENT1:
          {
            cerr << "\n   ~~~ MUX: SYN_SENT STATE ~~~\n";
            // NO IMPLEMENTATION NEEDED
          }
          break;
          case ESTABLISHED:
          {
            cerr << "\n   ~~~ MUX: ESTABLISHED STATE ~~~\n";

            if (IS_FIN(receivedFlag))
            { // part16. activate close
              cerr << "FIN flagged.\n";
              sendSeqNum = cxn->state.GetLastSent() + data.GetSize() + 1;

              cxn->state.SetState(CLOSE_WAIT); //passive close
              cxn->state.SetLastSent(sendSeqNum);
              cxn->state.SetLastRecvd(recSeqNum);

              SET_ACK(sendFlag); //send back an ACK for the FIN received
              SendPacket(mux, Buffer(NULL, 0), conn, sendSeqNum, sendAckNum, cxn->state.GetRwnd(), sendFlag);

              //sending a request to the application layer asking it to verify closing a connection
              res.type = WRITE;
              res.connection = conn;
              res.bytes = 0;
              res.error = EOK;
              MinetSend(sock, res);
            }
            //else, is a dataflow packet
            else
            { 
              if (IS_ACK(receivedFlag) && cxn->state.GetLastRecvd() < recSeqNum)
              {
                cerr << "ACK is flagged." << endl;

                //packet has data
                if (data.GetSize() > 0)
                {
                  cerr << "The received packet has data" << endl;
                  cerr << "Recv: " << cxn->state.GetLastRecvd() << endl;
                
                  size_t recvBufferSize = cxn->state.GetRwnd();
                  //if there is an overflow of the received data
                  if (recvBufferSize < data.GetSize()) 
                  {
                    cxn->state.RecvBuffer.AddBack(data.ExtractFront(recvBufferSize)); //extract first n bits from data to recvbuffer
                    sendAckNum = recSeqNum + recvBufferSize - 1;
                    cxn->state.SetLastRecvd(sendAckNum);
                  }
                  else //if there is no overflow
                  {
                    cxn->state.RecvBuffer.AddBack(data);
                    sendAckNum = recSeqNum + data.GetSize() - 1;
                    cxn->state.SetLastRecvd(sendAckNum);
                  }

                  //grabbing the next sequence number to send 
                  sendSeqNum = cxn->state.GetLastSent() + min(recvBufferSize, data.GetSize());
                  cxn->state.SetLastSent(sendSeqNum);

                  //send an empty packet with ACK flag to mux to acknowledge the last received packet
                  SET_ACK(sendFlag);
                  SendPacket(mux, Buffer(NULL, 0), conn, sendSeqNum, sendAckNum + 1, cxn->state.GetRwnd(), sendFlag);

                  //create a socketrequestresponse to send to sock (its a write request to the socket)
                  res.type = WRITE;
                  res.connection = conn;
                  res.data = cxn->state.RecvBuffer; //send data in recvbuffer to sock
                  res.bytes = cxn->state.RecvBuffer.GetSize();
                  res.error = EOK;
                  MinetSend(sock, res);
                }
                else //we receive an empty ACK packet, and want to send our packet out of the send buffer using flow control
                { //second cycle, client sends an ACK to server 
                  cxn->state.SendBuffer.Erase(0, recAckNum - cxn->state.GetLastAcked() - 1);
                  cxn->state.N = cxn->state.N - (recAckNum - cxn->state.GetLastAcked() - 1);

                  cxn->state.SetLastAcked(recAckNum);
                  cxn->state.SetLastRecvd(recSeqNum);
                  cxn->state.last_acked = recAckNum;


                  cerr << "\nSend Buffer: ";
                  cxn->state.SendBuffer.Print(cerr);
                  cerr << endl;

                  cxn->state.N = cxn->state.N - (recAckNum - cxn->state.GetLastAcked() - 1);
  
                  // send some of the information in the buffer if there is an overflow in the sendbuffer
                  if (cxn->state.SendBuffer.GetSize() - cxn->state.GetN() > 0)
                  {
                    sendWithFlowControl(cxn, mux);
                  }
                  
                }
              }
            }
          }
          break;
          case SEND_DATA:
          {
            cerr << "\n   ~~~ MUX: SEND_DATA STATE ~~~\n";
            // NO IMPLEMENTATION NEEDED
          }
          break;
          case CLOSE_WAIT:
          {
            cerr << "\n   ~~~ MUX: CLOSE_WAIT STATE ~~~\n";
            //at this stage, need to wait for local user to terminate connection, then we send our own FIN
          }
          break;
          case FIN_WAIT1: //this state is after the client actively sent a FIN to the other user and is waiting for a response
          {
            cerr << "\n   ~~~ MUX: FIN_WAIT1 STATE ~~~\n";
            if (IS_FIN(receivedFlag)) //if other user sends a FIN back, we close the connection
            {
              sendSeqNum = cxn->state.GetLastSent() + data.GetSize() + 1;

              cxn->state.SetState(CLOSING); //set state to closing
              cxn->state.SetLastRecvd(recSeqNum); 
              cxn->state.SetLastSent(sendSeqNum);

              // set timeout
              cxn->bTmrActive = true;
              cxn->timeout = Time() + RTT;
              cxn->state.SetTimerTries(TMR_TRIES);

              SET_FIN(sendFlag); 
              SET_ACK(sendFlag); 
              SendPacket(mux, Buffer(NULL, 0), conn, sendSeqNum, sendAckNum, SEND_BUF_SIZE(cxn->state), sendFlag);
            }
            else if (IS_ACK(receivedFlag)) //received an ACK back after first sending a FIN, so set state to FIN_WAIT2
            {

              cxn->state.SetState(FIN_WAIT2);
              cxn->state.SetLastSent(sendSeqNum);
              cxn->state.SetLastAcked(recAckNum - 1);
            }
          }
          break;
          case CLOSING:
          {
            cerr << "\n   ~~~ MUX: CLOSING STATE ~~~\n";
            if (IS_ACK(receivedFlag))
            {
              cxn->state.SetState(TIME_WAIT);
              cxn->state.SetLastAcked(recAckNum - 1);
              cxn->state.SetLastRecvd(recSeqNum);
            }
          }
          break;
          case LAST_ACK:
          { //start of sending the second fin
            cerr << "\n   ~~~ MUX: LAST_ACK STATE ~~~\n";
            if (IS_ACK(receivedFlag))
            {
              cxn->state.SetState(LISTEN);
              cxn->state.SetLastAcked(recAckNum - 1);
              cxn->state.SetLastRecvd(recSeqNum);
            }
          }
          break;
          case FIN_WAIT2: //waiting for a FIN from the server, and then will send an ACK back and change to time_wait state
          {
            cerr << "\n   ~~~ MUX: FIN_WAIT2 STATE ~~~\n";
            if (IS_FIN(receivedFlag)) //if receive FIN from server, will send an ACK back to server and change to time_wait state
            {
              sendSeqNum = cxn->state.GetLastSent() + data.GetSize() + 1;

              cxn->state.SetState(TIME_WAIT);
              cxn->state.SetLastRecvd(recSeqNum);
              cxn->state.SetLastSent(sendSeqNum);
              cxn->state.SetLastAcked(recAckNum - 1);
 
              // set timeout
              cxn->bTmrActive = true;
              cxn->timeout = Time() + RTT;
              cxn->state.SetTimerTries(TMR_TRIES);

              //send ACK back to server after receiving their FIN
              SET_ACK(sendFlag); 
              SendPacket(mux, Buffer(NULL, 0), conn, sendSeqNum, sendAckNum, SEND_BUF_SIZE(cxn->state), sendFlag);
            }
          }
          break;
          case TIME_WAIT:
          {
            cerr << "\n   ~~~ MUX: TIME_WAIT STATE ~~~\n";
            cxn->timeout = Time() + 30;
            cxn->state.SetState(CLOSED);
          }
          break;
          default:
          {
            cerr << "\n   ~~~ MUX: DEFAULTED STATE ~~~\n";
          }
          break;
        }
      }
      // else there is no open connection
      else
      {
        cerr << "Could not find matching connection\n";
      }
      cerr << "\n~~~ END OF IP LAYER ~~~ \n";
    }

    //  Data from above the Socket layer
    else if (event.handle == sock) 
    {
      cerr << "\n~~~ START OF SOCKET LAYER ~~~ \n";
      SockRequestResponse req;
      SockRequestResponse res;
      MinetReceive(sock, req);
      Packet sndPacket;
      unsigned char sendFlag;
      cerr << "Received Socket Request:" << req << endl;

      switch(req.type)
      {
        case CONNECT:
        {
          cerr << "\n   ~~~ SOCK: CONNECT ~~~\n";

          unsigned int initialSeqNum = rand(); // Can make this a specific wierd value rather than the rand() function.
          TCPState connectConn(initialSeqNum, SYN_SENT, TMR_TRIES); //state is SYN_SENT
          connectConn.N = 0; // number of packets allowed in flight
          ConnectionToStateMapping<TCPState> newConn(req.connection, Time(), connectConn, true); // sets properties for connection, timeout, state, timer
          connectionsList.push_front(newConn); // Add this new connection to the list of connections
         
	  sendFlag = 0;
          res.type = STATUS;
          res.error = EOK; 
          cerr << "sending to sock"<<endl;
          MinetSend(sock, res); //send an ok status to sock
          cerr<<"sent to sock"<<endl;
          SET_SYN(sendFlag);
          cerr<< "Sneding SYNed flag to mux"<<endl;
          SendPacket(mux, Buffer(NULL, 0), newConn.connection, initialSeqNum, 0, SEND_BUF_SIZE(newConn.state), sendFlag);

          cerr << "\n~~~ SOCK: END CONNECT ~~~\n";
        }
        break;
        case ACCEPT:
        {
          // passive open
          cerr << "\n   ~~~ SOCK: ACCEPT ~~~\n";

          TCPState acceptConnection(rand(), LISTEN, TMR_TRIES);
          acceptConnection.N = 0;
          ConnectionToStateMapping<TCPState> newConnection(req.connection, Time(), acceptConnection, false); //new connection with accept connection state
          connectionsList.push_front(newConnection); //push newconnection to connection list
         
          res.type = STATUS;
          res.connection = req.connection;
          res.bytes = 0;
          res.error = EOK;
          cerr << "sending to sock"<<endl;
          MinetSend(sock, res); //send sockrequestresponse to sock
          cerr<<"sent to sock"<<endl;
          
          cerr << "\n   ~~~ SOCK: END ACCEPT ~~~\n";
        }
        break;
        case WRITE: 
        {
          cerr << "\n   ~~~ SOCK: WRITE ~~~\n";

          ConnectionList<TCPState>::iterator cxn = connectionsList.FindMatching(req.connection);
          if (cxn != connectionsList.end() && cxn->state.GetState() == ESTABLISHED)
          {
            cerr << "\n   ~~~ SOCK: WRITE: CONNECTION FOUND ~~~\n";

            size_t sendBufferSize = SEND_BUF_SIZE(cxn->state);
            //if there is overflow in the sendbuffer
            if (sendBufferSize < req.bytes)
            {
              //add to some of the data from req to the sendbuffer
              cxn->state.SendBuffer.AddBack(req.data.ExtractFront(sendBufferSize));

              res.bytes = sendBufferSize; //size of res.data is the size of the send buffer
              res.error = EBUF_SPACE; //error to indicate lack fo buffer space
            }
            //otherwise if there is no overflow
            else
            {
              cxn->state.SendBuffer.AddBack(req.data);

              res.bytes = req.bytes;
              res.error = EOK;
            }
            
            cxn->state.SendBuffer.Print(cerr);
            cerr << endl;

            res.type = STATUS;
            res.connection = req.connection;
            MinetSend(sock, res);

            // send data from buffer using "Go Back N"
            sendWithFlowControl(cxn, mux);
          }
          else
          {
            cerr << "\n   ~~~ SOCK: WRITE: NO CONNECTION FOUND ~~~\n";
            res.connection = req.connection;
            res.type = STATUS;
            res.bytes = req.bytes;
            res.error = ENOMATCH;
          }
          
          cerr << "\n   ~~~ SOCK: END WRITE ~~~\n";
        }
        break;
        case FORWARD:
        {
          cerr << "\n   ~~~ SOCK: FORWARD ~~~\n";
          
          cerr << "\n   ~~~ SOCK: END FORWARD ~~~\n";
        }
        break;
        case CLOSE:
        {
          cerr << "\n   ~~~ SOCK: CLOSE ~~~\n";
          ConnectionList<TCPState>::iterator cxn = connectionsList.FindMatching(req.connection);
          if (cxn->state.GetState() == CLOSE_WAIT) //established connection, now call for close 
          {
            // timeout stuff
            cxn->bTmrActive = true;
            cxn->timeout = Time() + RTT;
            cxn->state.SetTimerTries(TMR_TRIES);
	    
	    sendFlag = 0;
            cxn->state.SetState(LAST_ACK);
            SET_FIN(sendFlag); //send fin to activate closing
            SET_ACK(sendFlag);
            SendPacket(mux, Buffer(NULL, 0), cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd() + 1, cxn->state.GetRwnd(), sendFlag);
          }
          cerr << "\n   ~~~ SOCK: END CLOSE ~~~\n";
        }
        break; 
        case STATUS: 
        {
          cerr << "\n   ~~~ SOCK: STATUS ~~~\n";
          ConnectionList<TCPState>::iterator cxn = connectionsList.FindMatching(req.connection);
          if (cxn->state.GetState() == ESTABLISHED)
          {
            cerr << req.bytes << " out of " << cxn->state.RecvBuffer.GetSize() << " bytes read" << endl;
            // if all data read
            if (req.bytes == cxn->state.RecvBuffer.GetSize())
            {
              cxn->state.RecvBuffer.Clear();
            }
            // if some data still in buffer
            else
            {
              cxn->state.RecvBuffer.Erase(0, req.bytes);

              //resend the WRITE request to the sock
              res.type = WRITE;
              res.connection = req.connection;
              res.data = cxn->state.RecvBuffer;
              res.bytes = cxn->state.RecvBuffer.GetSize();
              res.error = EOK;

              MinetSend(sock, res);
            }
          }
          cerr << "\n   ~~~ SOCK: END STATUS ~~~\n";
        }
        break;
        default:
        {
          cerr << "\n   ~~~ SOCK: DEFAULT ~~~\n";
          cerr << "\n   ~~~ SOCK: END DEFAULT ~~~\n";
        } 
          // TODO: responsd to request with
        break;

      }

      cerr << "\n~~~ END OF SOCKET LAYER ~~~ \n";

    }
  }
  return 0;
}


//helper function to make a packet
Packet MakePacket(Buffer data, Connection conn, unsigned int seq_n, unsigned int ack_n, size_t win_size, unsigned char flag)
{
  // create the Packet
  unsigned size = MIN_MACRO(IP_PACKET_MAX_LENGTH-TCP_HEADER_MAX_LENGTH, data.GetSize());
  Packet sndPacket(data.ExtractFront(size));

  // then create and push IP header
  IPHeader sendIPheader;
  sendIPheader.SetProtocol(IP_PROTO_TCP);
  sendIPheader.SetSourceIP(conn.src);
  sendIPheader.SetDestIP(conn.dest);
  sendIPheader.SetTotalLength(size + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
  sndPacket.PushFrontHeader(sendIPheader);

  // then create and push TCP header
  TCPHeader sendTCPheader;
  sendTCPheader.SetSourcePort(conn.srcport, sndPacket);
  sendTCPheader.SetDestPort(conn.destport, sndPacket);
  sendTCPheader.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, sndPacket);
  sendTCPheader.SetFlags(flag, sndPacket);
  sendTCPheader.SetWinSize(win_size, sndPacket); // to fix
  sendTCPheader.SetSeqNum(seq_n, sndPacket);
  if (IS_ACK(flag))
  {
    sendTCPheader.SetAckNum(ack_n, sndPacket);
  }
  sendTCPheader.RecomputeChecksum(sndPacket);
  sndPacket.PushBackHeader(sendTCPheader);

  cerr << "~~~MAKING PACKET~~~" << endl;
  cerr << sendIPheader << endl;
  cerr << sendTCPheader << endl;
  cerr << sndPacket << endl;

  return sndPacket;
}

void sendWithFlowControl(ConnectionList<TCPState>::iterator cxn, MinetHandle mux) {
  unsigned int numInflight = cxn->state.GetN(); //packets in flight
  unsigned int recWindow = cxn->state.GetRwnd(); //receiver congestion window
  size_t sndWindow = cxn->state.SendBuffer.GetSize(); //sender congestion window
  Buffer data;

  while(numInflight < MAX_INFLIGHT && sndWindow != 0 && recWindow != 0) 
  {
    cerr << "\n numInflight: " << numInflight << endl;
    cerr << "\n recWindow: " << recWindow << endl;
    cerr << "\n sndWindow: " << sndWindow << endl;
    unsigned char sendFlag = 0;
    Packet sndPacket;

    // if MSS < recWindow and MSS < sndWindow, there is still space in both the recWindow and sndWindow
    if(MSS < recWindow && MSS < sndWindow)
    {
      cerr << "There is still space in the receiver window and sender window" << endl; 
      data = cxn->state.SendBuffer.Extract(numInflight, MSS); //extract data of size MSS from send buffer (offset of # packets inflight)
      // set the new sequence number and then move on to the next set of packets
      numInflight = numInflight + MSS;
      CLR_SYN(sendFlag);
      SET_ACK(sendFlag);
      SET_PSH(sendFlag);
      sndPacket = MakePacket(data, cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd() + 1, SEND_BUF_SIZE(cxn->state), sendFlag);

      cxn->state.SetLastSent(cxn->state.GetLastSent() + MSS); //adjust LastSent to account for the MSS just sent
    }
    // else there space is not enough space in sender window or receiver window
    else
    {
      cerr << "Limited space in either sender window or receiver window" << endl;
      data = cxn->state.SendBuffer.Extract(numInflight, min((int)recWindow, (int)sndWindow)); //extract data of size min(windows) from send buffer
      // set the new sequence number and then move on to the next set of packets
      numInflight = numInflight + min((int)recWindow, (int)sndWindow);
      CLR_SYN(sendFlag);
      SET_ACK(sendFlag);
      SET_PSH(sendFlag);
      sndPacket = MakePacket(data, cxn->connection, cxn->state.GetLastSent(), cxn->state.GetLastRecvd() + 1, SEND_BUF_SIZE(cxn->state), sendFlag);
      cxn->state.SetLastSent(cxn->state.GetLastSent() + min((int)recWindow, (int)sndWindow));
    }

    MinetSend(mux, sndPacket); //send the packet to mux
    
    recWindow = recWindow - numInflight;
    sndWindow = sndWindow - numInflight;                

    cerr << "\n numInflight: " << numInflight << endl;
    cerr << "recWindow: " << recWindow << endl;
    cerr << "sndWindow: " << sndWindow << endl;
    
    //set a timer that times out
    cxn->bTmrActive = true;
    cxn->timeout = Time() + RTT;
  }

  cxn->state.N = numInflight;
}

//helper function to make packet and send it using Minet
void SendPacket(MinetHandle handle, Buffer data, Connection conn, unsigned int seq_n, unsigned int ack_n, size_t win_size, unsigned char flag)
{
  Packet pack = MakePacket(data, conn, seq_n, ack_n, win_size, flag); // ack
  MinetSend(handle, pack);
}

//helper function to receive a packet from a handle using minet and save it to a packet
Packet ReceivePacket(MinetHandle handle) 
{
  Packet pack;
  MinetReceive(handle, pack);
  return pack;
}
