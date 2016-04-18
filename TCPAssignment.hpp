/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////                                    TCP Header                               ////////////////////////////////
////             Source Port(16bits)                       /////////////////////             Destination Port(16bits)           /////////
////                                                        Sequence Number(32bits)                                             /////////
/// Data Offset(4bits) // Reserved(6bits, 000000) // Control Bits(6bits) ///                 Windows(16bits)                    /////////
////              Checksum(16bits)                          ////////////////////               Urgent Pointer(16bits)           /////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct TCPHeader {
	uint16_t src_port; //source port
	uint16_t dst_port; //destination port
	uint32_t sequence_num; //sequence number
	uint32_t ack_num; //acknowledgement number

	/*
	uint8_t offset; //offset

	//control bits;
	uint8_t urg; // & 0x20
	uint8_t ack; // & 0x10
	uint8_t psh; // & 0x08
	uint8_t rst; // & 0x04
	uint8_t syn; // & 0x02
	uint8_t fin; // & 0x01
	 */
	uint16_t off_control; //offset + reserved + control bits

	uint16_t window; //window
	uint16_t checksum; //checksum
	uint16_t urg_ptr; //urgent pointer
};

enum State //to implement TCP 3-way handshaking
{ 
	SYN_SENT, //client - send SYN packet
	CLOSED, //server - port closed
	LISTEN, //server - port servicing
	SYN_RECEIVED, //server - get SYN and send SYN+ACK
	ESTABLISHED, //client - get SYN+ACK or server - get ACK
	//see http://mintnlatte.tistory.com/552
};

struct Connection
{
	uint32_t seq;
	uint32_t ack;
	sockaddr_in *src;
};

struct SocketData
{
	UUID socketUUID;
	int fd;
	int pid;
	uint8_t sin_family;
	uint16_t sin_port;
	struct in_addr sin_addr;
	socklen_t sin_addr_len;
	uint8_t pin_family;
	uint16_t pin_port;
	struct in_addr pin_addr;

	State state;
	int backlog;
	std::vector<Connection> backlogList;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	//add------------------------------------------------------------------------------
	virtual void syscall_socket(UUID syscallUUID, int family, int type, int protocol);
	virtual void syscall_close(UUID syscallUUID, int pid, int sockfd);
	virtual void syscall_read(UUID syscallUUID, int pid, int sockfd, void* buffer, size_t len);
	virtual void syscall_write(UUID syscallUUID, int pid, int sockfd, void* buffer, size_t len);
	//read & write - don't have to do now
	virtual void syscall_connect(UUID syscallUUID, int pid, int sockfd, 
		struct sockaddr *serv_addr, socklen_t addrlen);
	virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *clientaddr, socklen_t *addrlen);
	virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *my_addr, socklen_t addrlen);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr, socklen_t *addrlen);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr, socklen_t *addrlen);
	std::vector<SocketData*> socketList;
	//----------------------------------------------------------------------------
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */