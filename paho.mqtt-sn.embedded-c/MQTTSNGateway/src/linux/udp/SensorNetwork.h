/************************************************************************************
 * Contribution:	Secure Session Information (SSI) is added into the existing 
 * 					structure 'SensorNetwork' to manage encrypted traffic from Sensors
 * Date & Time:		June 08, 2019 | 19:09 PM
 * Contributor:		Bilal Imran 
 * Project:			OneM2M Framework for Constrained IoT Devices
 * Institution:		Al-Khwarizmi Institute of Computer Science (KICS), University
 * 					of Engineering and Technology Lahore (UET), Pakistan
 * Funding Agency:	National Centre for Cyber Security (NCCS), HEC Gov. Pakistan 
*************************************************************************************/
/**************************************************************************************
 * Copyright (c) 2016, Tomoaki Yamaguchi
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Tomoaki Yamaguchi - initial API and implementation and/or initial documentation
 **************************************************************************************/

#ifndef SENSORNETWORK_H_
#define SENSORNETWORK_H_

#include "MQTTSNGWDefines.h"
#include <string>
#include <sstream>

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <regex>
#include <string>
#include <stdlib.h>

#include "MQTTSNGWProcess.h"

#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <inttypes.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

using namespace std;

namespace MQTTSNGW
{

#ifdef  DEBUG_NWSTACK
  #define D_NWSTACK(...) printf(__VA_ARGS__)
#else
  #define D_NWSTACK(...)
#endif

/*===========================================
 Class  SensorNetAddreess
 ============================================*/
class SensorNetAddress
{
public:
	SensorNetAddress();
	~SensorNetAddress();
	void setAddress(uint32_t IpAddr, uint16_t port);
	int  setAddress(string* data);
	uint16_t getPortNo(void);
	uint32_t getIpAddress(void);
	bool isMatch(SensorNetAddress* addr);
	SensorNetAddress& operator =(SensorNetAddress& addr);
	char* sprint(char* buf);
	
private:
	uint16_t _portNo;
	uint32_t _IpAddr;
};

/*========================================
 Class UpdPort
 =======================================*/
class UDPPort
{
public:
	UDPPort();
	virtual ~UDPPort();

	int open(const char* ipAddress, uint16_t multiPortNo,	uint16_t uniPortNo);
	void close(void);
	int unicast(const uint8_t* buf, uint32_t length, SensorNetAddress* sendToAddr);
	int broadcast(const uint8_t* buf, uint32_t length);
	int recv(uint8_t* buf, uint16_t len, SensorNetAddress* addr);
	int get_sockfdUnicast();
	void set_sockfdUnicast(int Sock) { _sockfdUnicast = Sock; };
	SensorNetAddress get_SNAddr() { return _clientAddr; };
	
	sockaddr_in addru;

private:
	void setNonBlocking(const bool);
	int recvfrom(int sockfd, uint8_t* buf, uint16_t len, uint8_t flags,	SensorNetAddress* addr);

	int _sockfdUnicast;
	int _sockfdMulticast;

	SensorNetAddress _grpAddr;
	SensorNetAddress _clientAddr;
	bool _disconReq;

};

/*===========================================
 Class  SensorNetwork
 ============================================*/

/* DTLS Support
 * 
 * ... Any one '1' of the following three '3' options should be defined, not more than one '1' else it would fail
 * during the compilation process ...
 * 
 * <NO-DTLS> 		USE_NO_DTLS 
 * <DTLS-with-PSK> 	USE_NO_CERT
 * <DTLS-with-CERT> USE_NO_PSK
 * */
 
#define USE_NO_CERT 			
//#define USE_NO_PSK
//#define USE_NO_DTLS

class SensorNetwork: public UDPPort
{
public:
	SensorNetwork();  // Sensor Network Constructor
	~SensorNetwork(); // Sensor Network Destruction

	int unicast(const uint8_t* payload, uint16_t payloadLength, SensorNetAddress* sendto); // Sending data to a single Client
	int unicast2(SSL* _ssl, const uint8_t* payload, uint16_t payloadLength, SensorNetAddress* sendto); // Sending data to a single Client
	int broadcast(const uint8_t* payload, uint16_t payloadLength);						   // Sending data to a list of Clients
	int read(SSL* _ssl, uint8_t* buf, uint16_t bufLen);                                               // Reading data from a Client
	int initialize(void);															 	   // Sensor Network Initialization
	const char* getDescription(void);													
	SensorNetAddress* getSenderAddress(void);
	void setmIP (uint32_t str) { 
		_clientAddr.setAddress(str, htons(6667));
	};
	
	void set (SSL* _ssl) {
		ssl = _ssl;
	};
	
	const char* caFILE;
	const char* caKEY;
	const char* srvFILE;
	const char* srvKEY;
	const char* pskIDENTITY;
	const char* pskHINT;
	int mPortNo;
	int uPortNo;
	const char* ipAddr;
	int mode;
	int secure;
	const char* client_id; 
	int sock;
	
	
	BIO *bio;
	struct timeval timeout;

	union {
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
	} srvAddr, cltAddr; 
		
	std::string mIP;		
	SSL_CTX *ctx;
	SSL *ssl;
	
private:
	SensorNetAddress _clientAddr;   // Sender's address. not gateway's one.
	string _description;
};

}
#endif /* SENSORNETWORK_H_ */
