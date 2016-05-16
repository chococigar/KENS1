/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
	socketList = std::vector<SocketData*>();
	acceptQueue = std::vector<AcceptData*>();
}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void printPacketContent(Packet* packet)
{
	uint8_t buffer[1];
	for (unsigned int i = 0; i < packet->getSize(); i++)
	{
		if (i % 8 == 0 && i != 0)
			printf("\n");
		packet->readData(i, buffer, 1);
		printf("%02x ", *buffer);
	}
	printf("\n");
}

void TCPAssignment::print_socket(SocketData* socket)
{
	printf("socket info:\n");
	printf("fd : %d, pid: %d\n", socket->fd, socket->pid);
	printf("local: port: %04x, ip: %08x\n", socket->sin_port, socket->sin_addr.s_addr);
	printf("remote: port: %04x, ip: %08x\n", socket->pin_port, socket->pin_addr.s_addr);
	//printf("socketlength = %d\n", socket->sin_addr_len);
	printf("State = %d\n", socket->state);
	printf("backlog = %d, pending = %d, accepted = %d\n", socket->backlog, socket->pendingConnections, socket->accepted);
	printf("\n");
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	//std::cout << "packetArrived() : ";

	//printPacketContent(packet);
	
	uint8_t src_ip[4];
	uint8_t dest_ip[4];
	uint32_t src_ip_32;
	uint32_t dest_ip_32;

	packet->readData(14+12, src_ip, 4);
	packet->readData(14+16, dest_ip, 4);
	memcpy(&src_ip_32, src_ip, 4);
	memcpy(&dest_ip_32, dest_ip, 4);
	
	struct TCPHeader header;
	packet->readData(34, &header, sizeof(struct TCPHeader));
	uint16_t TCP_control = ntohs(header.off_control);
	
	if(!check_tcp_checksum(&header, src_ip_32, dest_ip_32))
	{
		printf("checksum failed\n");
		freePacket(packet);
		return;
	}
	//printf("port = %04x, ip = %08x\n", header.dst_port, dest_ip_32);

	struct SocketData *socketData;
	if ((TCP_control & 0x02) && !(TCP_control & 0x10)) //server gets syn
	{
		//printf("syn!\n");
		//printf("packetInfo: dst_addr = %08x, dst_port = %04x, src_addr = %08x, src_port = %04x\n",
		//	dest_ip_32, header.dst_port, src_ip_32, header.src_port);
		//find socket with matching dest ip, port, in listening state, and with pendingconnections less than backlog
		bool found = false;
		for (int i = 0; i < (int)socketList.size(); i++)
		{
			socketData = socketList[i];
			if((socketData->sin_addr.s_addr == dest_ip_32 || socketData->sin_addr.s_addr == INADDR_ANY)
				&& socketData->sin_port == header.dst_port
				&& socketData->state == State::LISTEN
				&& socketData->pendingConnections < socketData->backlog)
			{
				found = true;
				break;
			}
		}
		if (!found)
		{
			//printf("syn target socket not found\n");
			freePacket(packet);
			return;
		}
		printf("syn recv: start handshake\n");
		printf("packetInfo: dst_addr = %08x, dst_port = %04x, src_addr = %08x, src_port = %04x\n",
			dest_ip_32, header.dst_port, src_ip_32, header.src_port);
		print_socket(socketData);
		socketData->pendingConnections += 1;

		//make child socket
		SocketData* childSocketData = new SocketData;
		memcpy(childSocketData, socketData, sizeof(SocketData));
		childSocketData->state = State::SYN_RECEIVED;
		childSocketData->pin_family = socketData->sin_family;
		childSocketData->pin_port = header.src_port;
		childSocketData->pin_addr.s_addr = src_ip_32;
		socketList.push_back(childSocketData);
		printf("child socket: ");
		print_socket(childSocketData);
		

		struct TCPHeader newHeader;
		memcpy(&newHeader, &header, sizeof(TCPHeader));
		//change source port and destination port
		newHeader.src_port = header.dst_port;
		newHeader.dst_port = header.src_port;
		//header length in word, reserved bits, ack and syn flag on. 
		newHeader.off_control = htons(0x5012);		
		//seq num increases by 1
		newHeader.sequence_num = htonl(ntohl(header.sequence_num) + 1);
		//ack num equal to seq
		newHeader.ack_num = newHeader.sequence_num;
		//calculate checksum
		newHeader.checksum = 0;
		add_tcp_checksum(&newHeader, dest_ip_32, src_ip_32);


		Packet *newPacket = clonePacket(packet);
		newPacket->writeData(14+12, dest_ip, 4);
		newPacket->writeData(14+16, src_ip, 4);
		newPacket->writeData(34, &newHeader, sizeof(TCPHeader));
		sendPacket("IPv4", newPacket);

		freePacket(packet);
		return;
	}
	else if (TCP_control & 0x02 && TCP_control & 0x10) //syn + ack
	{
		printf("syn+ack!\n");
		bool found = false;
		//find socket with matching src_ip, src_port, dst_ip, dst_port and with state SYN_SENT
		for (int i = 0; i < (int)socketList.size(); i++)
		{
			socketData = socketList[i];
			if((socketData->sin_addr.s_addr == *dest_ip || socketData->sin_addr.s_addr == INADDR_ANY)
				&& socketData->sin_port == header.dst_port
				&& socketData->pin_addr.s_addr == *src_ip
				&& socketData->pin_port == header.src_port
				&& socketData->state == State::SYN_SENT)
			{
				found = true;
				break;
			}
		}
		if(!found)
		{
			printf("SYN_SENT socket not found\n");
			freePacket(packet);
			return;
		}
		printf("SYN_SENT socket found\n");
		
		struct TCPHeader newHeader;

		memcpy(&newHeader, &header, sizeof(TCPHeader));

		//change source port and destination port
		newHeader.src_port = header.dst_port;
		newHeader.dst_port = header.src_port;

		newHeader.off_control = header.off_control | 0x10;
		newHeader.off_control = header.off_control ^ 0x02; //ack only
		newHeader.checksum = 0; //TODO: calculate checksum
		add_tcp_checksum(&newHeader, dest_ip_32, src_ip_32);

		Packet *newPacket = allocatePacket(packet->getSize());
		newPacket->writeData(14+12, dest_ip, 4);
		newPacket->writeData(14+16, src_ip, 4);
		newPacket->writeData(34, &newHeader, sizeof(TCPHeader));

		this->sendPacket("IPv4", newPacket);
		this->freePacket(packet);

		socketData->state = ESTABLISHED;
		
		//now return connect systemcall
		for (int i = 0; i < (int)acceptQueue.size(); i++)
		{
			if (acceptQueue[i]->sockfd == socketData->fd
				&& acceptQueue[i]->pid == socketData->pid)
			{
				/*
				syscall_accept(acceptQueue[i]->syscallUUID, 
					acceptQueue[i]->pid,
					acceptQueue[i]->sockfd,
					acceptQueue[i]->clientaddr,
					acceptQueue[i]->addrlen);
					*/
				//assign new file desriptor
				returnSystemCall(acceptQueue[i]->syscallUUID, socketData->fd);
				free(acceptQueue[i]);
				acceptQueue.erase(acceptQueue.begin()+i);
				//TODO: copy the same behavior from accept syscall
				printf("connect is unblocked\n");
				break;
			}
		}

		return;
	}
	else if (TCP_control & 0x10) //ack
	{
		printf("ack!\n");
		printf("packetInfo: dst_addr = %08x, dst_port = %04x, src_addr = %08x, src_port = %04x\n",
			dest_ip_32, header.dst_port, src_ip_32, header.src_port);
		bool found = false;
		printf("showing all sockets:\n");
		for (int i = 0; i < (int)socketList.size(); i++)
		{
			print_socket(socketList[i]);
		}
		for (int i = 0; i < (int)socketList.size(); i++)
		{
			socketData = socketList[i];
			if((socketData->sin_addr.s_addr == dest_ip_32 || socketData->sin_addr.s_addr == INADDR_ANY)
				&& socketData->sin_port == header.dst_port
				&& socketData->pin_addr.s_addr == src_ip_32
				&& socketData->pin_port == header.src_port
				&& socketData->state == State::SYN_RECEIVED)
			{
				found = true;
				break;
			}
		}
		if(!found)
		{
			printf("ack target socket not found!\n");
			freePacket(packet);
			return;
		}
		printf("establishing connection\n");
		socketData->state = State::ESTABLISHED;
		print_socket(socketData);

		//TODO: decrease pending connection count of parent socket
		for (int i = 0; i < (int)socketList.size(); i++)
		{
			if((socketList[i]->sin_addr.s_addr == dest_ip_32 || socketList[i]->sin_addr.s_addr == INADDR_ANY)
				&& socketList[i]->sin_port == header.dst_port
				&& socketList[i]->state == State::LISTEN)
			{
				socketList[i]->pendingConnections -= 1;
				break;
			}
		}

		// process pending accept requests
		for (int i = 0; i < (int)acceptQueue.size(); i++)
		{
			if (acceptQueue[i]->sockfd == socketData->fd)
			{
				//assign new file desriptor
				int fd = createFileDescriptor(socketData->pid);
				socketData->fd = fd;
				socketData->accepted = true;

				sockaddr_in *clientaddr_in = (sockaddr_in*)acceptQueue[i]->clientaddr;
				clientaddr_in->sin_family = socketData->pin_family;
				clientaddr_in->sin_port = socketData->pin_port;
				clientaddr_in->sin_addr.s_addr = socketData->pin_addr.s_addr;
				*acceptQueue[i]->addrlen = socketData->sin_addr_len;

				returnSystemCall(acceptQueue[i]->syscallUUID, fd);
				free(acceptQueue[i]);
				acceptQueue.erase(acceptQueue.begin()+i);
				printf("accept is unblocked\n");
				break;
			}
		}
	}
	else
	{
		freePacket(packet);
		return;
	}
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type)
{
	int fd;
	if((fd = createFileDescriptor(pid)) == -1)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	printf("(pid:%d) socket(): fd = %d\n", pid, fd);
	SocketData* socketData = new SocketData;
	socketData->socketUUID = syscallUUID;
	socketData->fd = fd;
	socketData->pid = pid;
	socketData->sin_family = 0;
	socketData->sin_port = 0;
	socketData->state = State::CLOSED;
	socketList.push_back(socketData);
	print_socket(socketData);

	returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
	//TODO: find socketData from list using sockfd
	printf("(pid:%d) close(%d)\n", pid, sockfd);
	bool found = false;
	for (int i = socketList.size()-1; i >= 0; i--)
	{
		if (socketList[i]->fd == sockfd &&
			socketList[i]->pid == pid)
		{
			delete socketList[i];
			socketList.erase(socketList.begin()+i);
			found = true;
			break;
		}
	}
	if(!found) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	//TODO: remove socketData from list
	removeFileDescriptor(pid, sockfd);
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void* buffer, size_t len)
{
	//syscall_read - don't have to implement now.
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, void* buffer, size_t len)
{
	//syscall_write - don't have to implement now.
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, 
	struct sockaddr *serv_addr, socklen_t addrlen)
{
	//TODO: find socketData from list using sockfd
	printf("(pid:%d) connect(%d) : ", pid, sockfd);

	
	struct SocketData *socketData;
	bool found = false;
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		socketData = socketList[i];
		if (socketData->fd == sockfd &&
			socketData->pid == pid &&
			socketData->state == State::CLOSED)
		{
			found = true;
			break;
		}
	}
	if(!found)
	{
		printf("socket not found\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}

	sockaddr_in *serv_addr_in = (sockaddr_in*)serv_addr;
	socketData->pin_family = serv_addr_in->sin_family;
	socketData->pin_port = serv_addr_in->sin_port;
	socketData->pin_addr.s_addr = serv_addr_in->sin_addr.s_addr;
	socketData->state = State::SYN_SENT;

	struct TCPHeader newHeader;

	newHeader.src_port = socketData->sin_port;
	newHeader.dst_port = socketData->pin_port;

	newHeader.sequence_num = 0;
	newHeader.ack_num = 0;
	newHeader.off_control = htons(0x5002);
	newHeader.checksum = 0; //TODO: calculate checksum
	add_tcp_checksum(&newHeader, socketData->pin_addr.s_addr, socketData->sin_addr.s_addr);

	Packet *newPacket = allocatePacket(sizeof(Packet));
	newPacket->writeData(14+12, &(socketData->sin_addr.s_addr), 4);
	newPacket->writeData(14+16, &(socketData->pin_addr.s_addr), 4);
	newPacket->writeData(34, &newHeader, sizeof(TCPHeader));

	this->sendPacket("IPv4", newPacket);

	//let's pretend that client has a ConnectQueue, but let's use Acceptqueue for now.
	AcceptData* acceptData = new AcceptData;
	acceptData->syscallUUID = syscallUUID;
	acceptData->pid = pid;
	acceptData->sockfd = sockfd;
	acceptData->clientaddr = serv_addr;
	//acceptData->addrlen = addrlen;
	acceptQueue.push_back(acceptData);

	//returnsystemcall is called when you get correct ACK packet.
	//returnSystemCall(syscallUUID, 0);
	return;
	
	
	
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	//TODO: find socketData from list using sockfd
	struct SocketData *socketData;
	bool found = false;
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		socketData = socketList[i];
		if (socketData->fd == sockfd
			&& socketData->state == State::CLOSED)
		{
			found = true;
			break;
		}
	}
	if(!found)
	{
		printf("listen: socket not found");
		returnSystemCall(syscallUUID, -1);
		return;
	}
	socketData->state = State::LISTEN;
	socketData->backlog = backlog;
	printf("listen(), sockfd = %d \n", sockfd);
	returnSystemCall(syscallUUID, 0);
	return;
}

//extract first connection request on the queue of pending connection for the listening socket.
//create new connected socket and return new file descriptor referring to that socket.
//original socket sockfd not affected by the call.
//clientaddr argument is the address of peer socket. when addr is null, nothing is filled in. addrlen is null too.
//addrlen argmument: on return it will contain the actual size of the peer address.
//if no pending connections are present on the queue, and the socket is not marked as nonblocking,
//accept() blocks the caller until a connection is present.
//if the socket is arked nonblocking and no pending connections are present on the queue, accept() fails.

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *clientaddr, socklen_t *addrlen)
{	
	printf("(pid:%d) accept(%d) : ", pid, sockfd);

	SocketData *socketData;
	bool found = false;

	//find a socket of sockfd, with complete connection
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		socketData = socketList[i];
		if (socketData->fd == sockfd &&
			socketData->pid == pid &&
			socketData->state == State::ESTABLISHED &&
			socketData->accepted == false)
		{
			found = true;
			break;
		}
	}
	//if not found, block accept (store in queue)
	if(!found)
	{
		printf("blocked\n");
		AcceptData* acceptData = new AcceptData;
		acceptData->syscallUUID = syscallUUID;
		acceptData->pid = pid;
		acceptData->sockfd = sockfd;
		acceptData->clientaddr = clientaddr;
		acceptData->addrlen = addrlen;
		acceptQueue.push_back(acceptData);
		return;
	}
	printf("not blocked\n");
	
	//return immediately
	int fd;
	if((fd = createFileDescriptor(pid)) == -1)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	socketData->fd = fd;
	socketData->accepted = true;

	sockaddr_in *clientaddr_in = (sockaddr_in*)clientaddr;
	clientaddr_in->sin_family = socketData->pin_family;
	clientaddr_in->sin_port = socketData->pin_port;
	clientaddr_in->sin_addr.s_addr = socketData->pin_addr.s_addr;
	*addrlen = socketData->sin_addr_len;

	//decrease pending connection count of parent socket
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if((socketList[i]->sin_addr.s_addr == socketData->sin_addr.s_addr || socketList[i]->sin_addr.s_addr == INADDR_ANY)
			&& socketList[i]->sin_port == socketData->sin_port
			&& socketList[i]->state == State::LISTEN)
		{
			socketList[i]->pendingConnections -= 1;
			break;
		}
	}

	returnSystemCall(syscallUUID, fd);
	return;
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t addrlen)
{
	bool found = false;
	//TODO: check if port is already being used by another socket in the list.
	//however differet IP can use same port number.
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;

	printf("(pid:%d) bind(%d): port = %04x, ip = %08x\n", pid, sockfd, addr_in->sin_port, addr_in->sin_addr.s_addr);

	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if(socketList[i]->sin_port == addr_in->sin_port 
			&& (socketList[i]->sin_addr.s_addr == addr_in->sin_addr.s_addr 
				|| socketList[i]->sin_addr.s_addr == INADDR_ANY))
		{
			printf("bind: socket with specified ip/port already exists.\n");
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd && 
			socketList[i]->pid == pid &&
			socketList[i]->state == State::CLOSED)
		{
			socketList[i]->sin_family = addr_in->sin_family;
			socketList[i]->sin_port = addr_in->sin_port;
			socketList[i]->sin_addr.s_addr = addr_in->sin_addr.s_addr;
			socketList[i]->sin_addr_len = addrlen;
			print_socket(socketList[i]);
			found = true;
			break;
		}
	}
	if(!found)
	{
		printf("bind: can't find socket\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}

	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t *addrlen)
{
	printf("getsockname(%d)", sockfd);
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
	bool found = false;
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd &&
			socketList[i]->pid == pid)
		{
			print_socket(socketList[i]);
			//TODO: initialize with findiing socketData
			addr_in->sin_family = socketList[i]->sin_family;
			addr_in->sin_port = socketList[i]->sin_port;
			addr_in->sin_addr.s_addr = socketList[i]->sin_addr.s_addr;
			*addrlen = socketList[i]->sin_addr_len;
			found = true;
			break;
		}
	}
	if(!found)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	returnSystemCall(syscallUUID, 0);

}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t *addrlen)
{
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
	bool found = false;
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd)// && socketList[i]->sin_family == -1)
		{
			addr_in->sin_family = socketList[i]->pin_family;
			printf("pin_family = %d\n", addr_in->sin_family);
			addr_in->sin_port = socketList[i]->pin_port;
			addr_in->sin_addr = socketList[i]->pin_addr;
			*addrlen = socketList[i]->sin_addr_len;
			found = true;
			break;
		}
	}
	if(!found)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::timerCallback(void* payload)
{

}

void TCPAssignment::add_tcp_checksum(TCPHeader *header, uint32_t src_ip, uint32_t dst_ip)
{
	header->checksum = 0;
	header->checksum = htons(~(NetworkUtil::tcp_sum(src_ip, dst_ip, (uint8_t*)header, sizeof(TCPHeader))));
}

bool TCPAssignment::check_tcp_checksum(TCPHeader* header, uint32_t src_ip, uint32_t dst_ip)
{
	uint16_t checksum = header->checksum;
	struct TCPHeader newHeader;
	memcpy(&newHeader, header, sizeof(TCPHeader));
	newHeader.checksum = 0;
	//if(checksum == htons(~(NetworkUtil::tcp_sum(src_ip, dst_ip, (uint8_t *)newHeader, sizeof(TCPHeader))))) return true;
	//return false;
	return checksum == htons(~(NetworkUtil::tcp_sum(src_ip, dst_ip, (uint8_t *)&newHeader, sizeof(TCPHeader))));
}

}