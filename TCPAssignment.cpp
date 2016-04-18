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
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	uint8_t src_ip[4];
	uint8_t dest_ip[4];
	packet->readData(14+12, src_ip, 4);
	packet->readData(14+16, dest_ip, 4);
	struct TCPHeader header;
	packet->readData(34, &header, sizeof(struct TCPHeader));
	uint16_t TCP_control = header.off_control;	
	
	struct SocketData *socketData;
	
	if (TCP_control & 0x02 && !TCP_control & 0x10) //server gets syn
	{
		bool found = false;
		for (int i = 0; i < (int)socketList.size(); i++)
		{
			socketData = socketList[i];
			if((socketData->sin_addr.s_addr == *dest_ip || socketData->sin_addr.s_addr == INADDR_ANY)
				&& socketData->sin_port == header.dst_port
				&& socketData->state == State::LISTEN)
			{
				found = true;
				break;
			}
		}
		if (!found)
		{
			freePacket(packet);
			return;
		}
		
		//TODO: save connection info??
		if(socketData->backlog > 0)
		{
			socketData->backlog -= 1;

			//SocketData* childSocketData = new SocketData;
			//memcpy(childSocketData, socketData, sizeof(SocketData));
			//childSocketData->state = State::SYN_RECEIVED;
			//childSocketData->pin_port = header.src_port;
			//childSocketData->pin_addr.s_addr = *src_ip;
			//socketList.push_back(childSocketData);
			socketData->state = State::SYN_RECEIVED;
			socketData->pin_family = socketData->sin_family;
			socketData->pin_port = header.src_port;
			socketData->pin_addr.s_addr = *src_ip;

			struct TCPHeader newHeader;
			memcpy(&newHeader, &header, sizeof(TCPHeader));

			//change source port and destination port
			newHeader.src_port = header.dst_port;
			newHeader.dst_port = header.src_port;

			newHeader.off_control = header.off_control | 0x12; //syn + ack
			newHeader.checksum = 0; //TODO: calculate checksum

			Packet *newPacket = allocatePacket(packet->getSize());
			newPacket->writeData(0, &newHeader, sizeof(TCPHeader));

			sendPacket("IPv4", newPacket);
			freePacket(packet);

			return;
		}
		else //backlog full
		{
			freePacket(packet);
			return;
		}
	}
	else if (TCP_control & 0x02 && TCP_control & 0x10) //syn + ack
	{
		bool found = false;
		for (int i = 0; i < (int)socketList.size(); i++)
		{
			socketData = socketList[i];
			if((socketData->sin_addr.s_addr == *dest_ip || socketData->sin_addr.s_addr == INADDR_ANY)
				&& socketData->sin_port == header.dst_port
				&& socketData->state == State::SYN_SENT)
			{
				found = true;
				break;
			}
		}
		if(!found)
		{
			freePacket(packet);
			return;
		}
		struct TCPHeader newHeader;

		memcpy(&newHeader, &header, sizeof(TCPHeader));

		//change source port and destination port
		newHeader.src_port = header.dst_port;
		newHeader.dst_port = header.src_port;

		newHeader.off_control = header.off_control | 0x10;
		newHeader.off_control = header.off_control ^ 0x02; //ack only
		newHeader.checksum = 0; //TODO: calculate checksum

		Packet *newPacket = allocatePacket(packet->getSize());
		newPacket->writeData(0, &newHeader, sizeof(TCPHeader));

		sendPacket("IPv4", newPacket);
		freePacket(packet);

		this->sendPacket("IPv4", newPacket);
		this->freePacket(packet);

		socketData->state = ESTABLISHED;
		return;
	}
	else if (TCP_control & 0x10) //ack
	{
		bool found = false;
		for (int i = 0; i < (int)socketList.size(); i++)
		{
			socketData = socketList[i];
			if((socketData->sin_addr.s_addr == *dest_ip || socketData->sin_addr.s_addr == INADDR_ANY)
				&& socketData->sin_port == header.dst_port
				&& socketData->pin_addr.s_addr == *src_ip
				&& socketData->pin_port == header.src_port
				&& socketData->state == State::SYN_RECEIVED)
			{
				found = true;
				break;
			}
		}
		if(!found)
		{
			freePacket(packet);
			return;
		}
		socketData->state = State::ESTABLISHED;
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
	SocketData* socketData = new SocketData;
	socketData->socketUUID = syscallUUID;
	socketData->fd = fd;
	socketData->pid = pid;
	socketData->sin_family = 0;
	socketData->sin_port = 0;
	socketData->state = State::CLOSED;
	socketList.push_back(socketData);
	returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
	//TODO: find socketData from list using sockfd
	bool found = false;
	for (int i = socketList.size()-1; i >= 0; i--)
	{
		if (socketList[i]->fd == sockfd)
		{
			delete socketList[i];
			socketList.erase(socketList.begin()+i);
			found = true;
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
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, void* buffer, size_t len)
{
	//syscall_write - don't have to implement now.
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, 
	struct sockaddr *serv_addr, socklen_t addrlen)
{
	//TODO: find socketData from list using sockfd
	if(0) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	//TODO: find socketData from list using sockfd
	struct SocketData *socketData;
	bool found = false;
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd)
		{
			socketData = socketList[i];
			found = true;
			break;
		}
	}
	if(!found || socketData->state != CLOSED) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	socketData->state = State::LISTEN;
	socketData->backlog = backlog;
	//socketData->backlog_queue = new Queue<struct Connection*>;
	//socketData->handshake_queue = new Queue<struct SocketData*>;
	returnSystemCall(syscallUUID, 0);
	return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *clientaddr, socklen_t *addrlen)
{	
	SocketData *socketData;
	bool found = false;
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		socketData = socketList[i];
		if (socketData->fd == sockfd
			&& socketData->state == State::ESTABLISHED)
		{
			found = true;
			break;
		}
	}
	if(!found)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	sockaddr_in *clientaddr_in = (sockaddr_in*)clientaddr;
	clientaddr_in->sin_family = socketData->pin_family;
	clientaddr_in->sin_port = socketData->pin_port;
	clientaddr_in->sin_addr.s_addr = socketData->pin_addr.s_addr;
	*addrlen = socketData->sin_addr_len;
	returnSystemCall(syscallUUID, 0);
	return;		
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *my_addr, socklen_t addrlen)
{
	//TODO: find socketData from list using sockfd
	bool found = false;
	//TODO: check if port is already being used by another socket in the list.
	//however differet IP can use same port number.
	struct sockaddr_in *addr_in = (struct sockaddr_in *)my_addr;
	auto port = addr_in->sin_port;	
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if(socketList[i]->sin_port == port 
			&& (socketList[i]->sin_addr.s_addr == addr_in->sin_addr.s_addr 
				|| socketList[i]->sin_addr.s_addr == INADDR_ANY))
		{
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd && socketList[i]->sin_family == 0)
		{
			socketList[i]->sin_family = addr_in->sin_family;
			socketList[i]->sin_port = addr_in->sin_port;
			socketList[i]->sin_addr = addr_in->sin_addr;
			socketList[i]->sin_addr_len = addrlen;
			
			found = true;
		}
	}
	if(!found) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}


	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t *addrlen)
{
	//TODO: find socketData from list using sockfd
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
	bool found = false;
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd) //&& socketList[i]->sin_family != 0)
		{
			//TODO: initialize with findiing socketData
			addr_in->sin_family = socketList[i]->sin_family;
			addr_in->sin_port = socketList[i]->sin_port;
			addr_in->sin_addr = socketList[i]->sin_addr;
			*addrlen = socketList[i]->sin_addr_len;
			found = true;
			break;
		}
	}
	if(!found) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	returnSystemCall(syscallUUID, 0);

}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t *addrlen)
{
	/*
	//TODO: find socketData from list using sockfd
	bool found = false;
	for (int i = 0; i < socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd && socketList[i]->sin_family == -1)
		{
			//TODO: initialize with findiing socketData
			struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
			addr_in->sin_family = socketList[i]->sin_family;
			addr_in->sin_port = socketList[i]->sin_port;
			addr_in->sin_addr = socketList[i]->sin_addr;
			found = true;
			break;
		}
	}
	if(!found) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	returnSystemCall(syscallUUID, 0);
	/*
	//TODO: find socketData from list using sockfd
	if(0) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	SocketData *socketData; //TODO: initialize with findiing socketData
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
	addr_in->sin_family = socketData->sin_family;
	addr_in->sin_port = socketData->sin_port;
	addr_in->sin_addr = socketData->sin_addr;
	returnSystemCall(syscallUUID, 0);
	*/
	returnSystemCall(syscallUUID, -1);

}

void TCPAssignment::timerCallback(void* payload)
{

}


}