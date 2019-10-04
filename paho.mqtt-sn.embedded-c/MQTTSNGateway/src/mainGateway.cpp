/************************************************************************************
 * File Name:		mainGateway.cpp
 * File Purpose:	This file contains detailed implementation of Multi-Threaded 
 * 			DTLS Server for MQTTSN gateway application.
 * Date & Time:		June 08, 2019 | 19:09 PM
 * Author:		Bilal Imran 
 * Project:		OneM2M Framework for Constrained IoT Devices
 * Institution:		Al-Khwarizmi Institute of Computer Science (KICS), University
 * 			of Engineering and Technology Lahore (UET), Pakistan
 * Funding Agency:	National Centre for Cyber Security (NCCS), HEC Gov. Pakistan 
*************************************************************************************/

/********************************************
 *  DTLS Control Parameter 
 * <DTLS-with-PSK> USE_PSK
 * <DTLS-with-CERT> USE_CERT
 * *****************************************/
//#define USE_CERT 			
#define USE_PSK

#define MaxThreads			25
#define MSGLEN				4096
#define MAX_PACKET_SIZE			1500
#define PSK_KEY_LENGTH			5 			
#define COOKIE_SECRET_LENGTH 		8
#define MaxRows				3
#define MaxColumns			2


#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <regex>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "MQTTSNGateway.h"
#include "MQTTSNGWBrokerRecvTask.h"
#include "MQTTSNGWBrokerSendTask.h"
#include "MQTTSNGWClientRecvTask.h"
#include "MQTTSNGWClientSendTask.h"
#include "MQTTSNGWPacketHandleTask.h"
using namespace MQTTSNGW;

Gateway gateway; 
PacketHandleTask  PHT(&gateway);
BrokerSendTask    BST(&gateway);
BrokerRecvTask    BRT(&gateway);
ClientSendTask    CST(&gateway);
ClientRecvTask 	  *CRT;

void* PackThread	(void* );	// for packet handling 
void* BrkSndThread	(void* );	// for broker send task
void* BrkRcvThread	(void* );	// for broker rcv task	
void* SNSndThread 	(void* );	// for client send task
void* SNRcvThread	(void* );	// for client recv task
pthread_t tid1, tid2, tid3, tid4, tid5;

/* Psk Look-UP Table (Psk-LUPT)
 * 'Row' represents the client entries
 * 'Column' represents the client's info such as;
 * <Column00> Device ID
 * <Column01> Psk_Identity
 * <Column02> Psk Value (in Hex) */
static const char* Psk_LuPT[MaxRows][MaxColumns] = {
{"AE123-LOCK@in.provider.com", "0102030405"},
{"AE456-LOCK@in.provider.com", "0504030201"},
{"CSE123-Gateway@in.provider.com", "0101020305"}}; 

// Global Variables
static const char* psk_hint 	= "bridge";
static int uniPortNo 		= 6667;
static const char* ipAddress 	= "192.168.0.61";
static char socketBUFF[MSGLEN];
static int cookie_initialized;
static unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
static char *mn_psk_key;
static char *mn_psk_identity;
static char *mn_package;

//	Function Declarations
static unsigned int psk_server_cb(SSL *ssl, const char *identity,
                                  unsigned char *psk,
                                  unsigned int max_psk_len);
static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);
static const char* FindPsk (const char* psk_id);

// Socket & SSL related Variables
int _sockfdUnicast;	   	
SSL_CTX *ctx;
SSL *ssl;
BIO *bio;
struct timeval timeout;
struct pass_info *info;

struct       sockaddr_in cliAddr;   /* our client's address */
struct       sockaddr_in servAddr;   /* our server's address */

union {
	struct sockaddr_storage ss;
	struct sockaddr_in s4;
} peer_addr;

// General Functions 
int UDPPortOpen(char* ip, uint16_t port);
int DTLSInitialize();
int dtls_verify_callback (int ok, X509_STORE_CTX *ctx);
int GatewayServerStart(char* ip, uint16_t port); 
void* ThreadControl(void*);

typedef struct {
    int count;
    int activefd;
    int size;
    unsigned char b[MSGLEN];
    SSL *ssl;
    union {
	struct sockaddr_storage ss;
	struct sockaddr_in s4;
    } cliAddr;
} threadArgs;

int 	      c;
int           on = 1;
int           res = 1;
int           bytesRcvd = 0;
socklen_t     cliLen;
socklen_t     len = sizeof(on);
unsigned char buf[MSGLEN];     

threadArgs* args;
pthread_t threadid[MaxThreads];
pthread_mutex_t lock;
bool DtlsPskEnable, DtlsCertEnable, DtlsDebug, TlsDebug;
char *GWIPAddress;
uint16_t GWPortNo	= 0;

int main(int argc, char** argv)
{	
	int rc;
	c = 0;
	// initialize the gateway
	gateway.initialize(argc, argv);
	gateway.run();
	
	// Debugging Flags
	DtlsDebug	= gateway.getGatewayParams().DtlsDebug;
	TlsDebug	= gateway.getGatewayParams().TlsDebug;
		
	// Flags for GWIPAddress and GWPortNo
	GWIPAddress 	= gateway.getGatewayParams().GWDTLSServerName;
	GWPortNo	= atoi(gateway.getGatewayParams().GWDTLSPortNo);
	
	// Flags for Enabling DTLS 
	DtlsPskEnable 	= gateway.getGatewayParams().DtlsPskEnable;
	DtlsCertEnable 	= gateway.getGatewayParams().DtlsCertEnable;
	
	if(DtlsDebug == true) {
		printf("GWIPAddress:	%s\n", GWIPAddress);
		printf("GWPortNo:	%u\n", (unsigned int) GWPortNo);
		printf("DtlsPskEnable: %d\n", DtlsPskEnable); 
		printf("DtlsCertEnable: %d\n", DtlsCertEnable);
	}
		
	/* SPIN the five main THREADs */
	pthread_create(&tid1, NULL, PackThread, NULL);
	pthread_create(&tid2, NULL, BrkSndThread, NULL);
	pthread_create(&tid3, NULL, BrkRcvThread, NULL);
	pthread_create(&tid4, NULL, SNSndThread, NULL);
	
	GatewayServerStart(GWIPAddress, GWPortNo);
	
	int res;
	while (1) {
		printf("Awaiting client connection on port %d\n", uniPortNo);
		memset(&threadid[c], 0, sizeof(threadid[c]));
		args = (threadArgs *) malloc(sizeof(threadArgs));	
		memset(&socketBUFF, 0, sizeof(socketBUFF));
		memset(&cliAddr, 0, sizeof(cliAddr));
		cliLen = sizeof(cliAddr);
	    
		do {
			bytesRcvd = (int)recvfrom(_sockfdUnicast, (char*) socketBUFF, MSGLEN, 0,
				(struct sockaddr*) &cliAddr, &cliLen);
		} while (bytesRcvd <= 0);

		if (bytesRcvd < 0) {
			printf("No clients in que, enter idle state\n");
			continue;
		}

		else if (bytesRcvd > 0) {
			/* put all the bytes from buf into args */
			memcpy(args->b, socketBUFF, MAX_PACKET_SIZE);
			args->size = bytesRcvd;
			if ((args->activefd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
				printf("Cannot create socket.\n");
				return -1;
			}

		res = setsockopt(args->activefd, SOL_SOCKET, SO_REUSEADDR, &on,
			sizeof(on));
		if (res < 0) {
			printf("Setsockopt SO_REUSEADDR failed.\n");
			return -1;
		}

#ifdef SO_REUSEPORT
                res = setsockopt(args->activefd, SOL_SOCKET, SO_REUSEPORT, &on,
                        sizeof(on));
                if (res < 0) {
                    printf("Setsockopt SO_REUSEPORT failed.\n");
                    return -1;    
                }
#endif

		if (::bind(args->activefd, (const struct sockaddr *)&servAddr, 
			sizeof(struct sockaddr_in)) != 0) {
			printf("Udp bind failed.\n");
			return -1;
		}   	
               
		if (::connect(args->activefd, (const struct sockaddr *)&cliAddr,
				sizeof(cliAddr)) != 0) {
			printf("Udp connect failed.\n");
			return -1;
			}
	}
        else {
            /* else bytesRcvd = 0 */
            printf("Recvfrom failed.\n");
            return -1;
        }
        printf("Connected!\n");
	args->count = c;
        /* SPIN A THREAD HERE TO HANDLE "buff" and "reply/ack" */
        pthread_create(&threadid[c], NULL, ThreadControl, args);
	sleep(2);
	c++;
    }
   
   pthread_join(tid1, 0);
   pthread_join(tid2, 0);
   pthread_join(tid3, 0);
   pthread_join(tid4, 0);
   pthread_join(tid5, 0);
    
   for (int j=0; j<c; j++) 
	pthread_join(threadid[j], 0);
   
   return 0;
}

void* PackThread   (void* arg) 	{
	PHT.run();
}
void* BrkSndThread (void* arg) 	{
	BST.run();
} 
void* BrkRcvThread (void* arg) 	{
	BRT.run();
}
void* SNSndThread  (void* arg) 	{
	CST.run();
} 
void* ThreadControl(void* openSock)
{
    int on 		= 1;
    threadArgs* args 	= (threadArgs*)openSock;
    int cn 		= args->count;
    pthread_t temp 	= threadid[cn];
    int                recvLen = 0;               
    int                activefd; 
    int                msgLen = args->size;        
    unsigned char      buff[MAX_PACKET_SIZE];              
    char               ack[] = "I hear you fashizzle!\n";
    SSL 	       *ssl;
    int                e;                      
    int 	       rc;
    uint32_t	       ip;
    char* 	       ipstr;
    memset(&args->cliAddr, 0, sizeof(struct sockaddr_storage));

    if ((ssl = SSL_new(ctx)) == NULL) {
	printf("SSL_new error.\n");
	goto END;
    } 
	
    bio = BIO_new_dgram(args->activefd, BIO_NOCLOSE);

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
	
    SSL_set_bio(ssl, bio, bio);
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

    int dtls_ret;
    do {
	dtls_ret = DTLSv1_listen(ssl, (BIO_ADDR *) &args->cliAddr);
    } while (dtls_ret <= 0); 

    int ret;
    do { 
	ret = SSL_accept(ssl);
    }
    while (ret <= 0);
	
    char* buf;
    if (ret < 0) {
	printf("%s\n", ERR_error_string(ERR_get_error(), buf));
	goto END;
    }
    	
    // Initiate the Client 
    CRT = (ClientRecvTask*) malloc (sizeof(ClientRecvTask));
    CRT = new ClientRecvTask(&gateway);
    CRT->addr = args->cliAddr.s4;
    CRT->ssl = ssl;
    CRT->_tid = temp;

    CRT->run();
    printf("Exiting child thread\n");
    goto END;

END:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(args->activefd);
    free(args);         
    pthread_exit(0); 
}

/* Psk-LUPT Associated Functions 
 * <Function01> Check if the called Psk_Identity is available inside LuPT, if so
 * then return the associated Psk Value */
const char* FindPsk (const char* psk_id) {
		int i = 0;
		while(i < MaxRows) {
			if (strcmp(Psk_LuPT[i][0], psk_id) != 0)
				i++;
			else
				return Psk_LuPT[i][1];
		}
		return "Not Found Psk-ID";
}

/* Psk Call-Back Functions */
unsigned int psk_server_cb(SSL *ssl, const char *identity,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    long key_len = 0;
    unsigned char *key;
    const char* psk_ret;
    	printf("Hello 04\n");	
    if (identity == NULL) {
        printf("Error: client did not send PSK identity\n");
        // goto out_err;
        printf("Error in PSK server callback\n");
		return 0;
    }
    
    /* here we could lookup the given identity e.g. from a database */
	printf("Hello 05\n");
	psk_ret = FindPsk(identity);
	if ( strcmp(psk_ret, "Not Found Psk-ID") == 0 ) {
		printf("[-] PSK warning: client identity not what we expected \n");
		printf("[-] Error in PSK server callback\n");
		return 0;
	}
	/*else
	printf("[.] PSK client identity found\n");*/
    
    /* convert the PSK key to binary */
    key = OPENSSL_hexstr2buf(psk_ret, &key_len);
    if (key == NULL) {
        printf("Could not convert PSK key '%s' to buffer\n", psk_ret);
        return 0;
    }
    if (key_len > (int)max_psk_len) {
        printf("psk buffer of callback is too small (%d) for key (%ld)\n",
                   max_psk_len, key_len);
        OPENSSL_free(key);
        return 0;
    }

    memcpy(psk, key, key_len);
    OPENSSL_free(key);

    //printf("fetched PSK len=%ld\n", key_len);
    return key_len;

/* out_err:
    printf("Error in PSK server callback\n");
    return 0; */
}

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
	} peer;

	/* Initialize a random secret */
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
			{
			printf("error setting random cookie secret\n");
			return 0;
			}
	
	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
				   &peer.s4.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port),
				   &peer.s4.sin_addr,
				   sizeof(struct in_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
	} peer;

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
				   &peer.s4.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s4.sin_addr,
				   sizeof(struct in_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);
	
	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0) {
			return 1;
	}
	
	return 0;
}

int DTLSInitialize() {	
/* Module 01:
 * [Start] SSL Session Creation via Context _ctx */
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLSv1_2_server_method());
/* We accept all ciphers, including NULL.
 * Not recommended beyond testing and debugging */	
// SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");
	SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
if (DtlsCertEnable == true) {	 
	if (!SSL_CTX_use_certificate_file(ctx, gateway.getGatewayParams().dtlscertKey, SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");
		
	if (!SSL_CTX_use_PrivateKey_file(ctx, gateway.getGatewayParams().dtlsprivateKey, SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, dtls_verify_callback);
}
if (DtlsPskEnable == true) {
	/* Use Psk & it's Psk-Hint */
	SSL_CTX_set_psk_server_callback(ctx, &psk_server_cb);
	SSL_CTX_use_psk_identity_hint(ctx, psk_hint);
}
	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);
	return 0;
}

int UDPPortOpen(char* _ipAddress, uint16_t _uniPortNo)
{
	char loopch = 0;
	const int reuse = 1;

	if (_uniPortNo == 0)
	{
		printf("error portNo undefined in UDPPort::open\n");
		return -1;
	}

	uint32_t ip = inet_addr(_ipAddress);
	
	/*------ Create unicast socket --------*/
	_sockfdUnicast = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (_sockfdUnicast < 0)
	{
		printf("error can't create unicast socket in UDPPort::open\n");
		return -1;
	}

	setsockopt(_sockfdUnicast, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(uniPortNo);
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (::bind(_sockfdUnicast, (sockaddr*) &servAddr, sizeof(servAddr)) < 0)
	{
		printf("fd1 error can't bind unicast socket in UDPPort::open\n");
		return -1;
	}
	return 0;
}

int GatewayServerStart(char* IP, uint16_t Port) {
	UDPPortOpen(IP, Port);
	DTLSInitialize();
}
