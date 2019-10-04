/********************************************************************************************
 * Contribution:	(1) Condition is added to exit the thread of that client who sends a
 * 			proper DISCONNECT packet
 * 			(2) SSI information update condition is added to update 'ssl'
 * 			to the current session made through DTLS
 * 			(3) client create methods via SSI are added to store SSI information
 * 			into the existing client list	
 * Date & Time:		June 08, 2019 | 19:09 PM
 * Contributor:		Bilal Imran 
 * Project:		OneM2M Framework for Constrained IoT Devices
 * Institution:		Al-Khwarizmi Institute of Computer Science (KICS), University
 * 			of Engineering and Technology Lahore (UET), Pakistan
 * Funding Agency:	National Centre for Cyber Security (NCCS), HEC Gov. Pakistan 
********************************************************************************************/
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

#include "MQTTSNGWClientRecvTask.h"
#include "MQTTSNPacket.h"
#include "MQTTSNGWQoSm1Proxy.h"
#include "MQTTSNGWEncapsulatedPacket.h"
#include <cstring>

#include <unistd.h>

//#include "MQTTSNGWForwarder.h"

using namespace MQTTSNGW;
char* currentDateTime(void);


#define OFF_THREADING

/*=====================================
 Class ClientRecvTask
 =====================================*/

SensorNetwork* ClientRecvTask::getSN() {
	return _sensorNetwork;
} 
 
ClientRecvTask::ClientRecvTask(Gateway* gateway)
{ 
	_gateway = gateway;
	_gateway->attach((Thread*)this);
	_sensorNetwork = _gateway->getSensorNetwork(); 
}

ClientRecvTask::~ClientRecvTask()
{

}


/**
 * Initialize SensorNetwork
 */
void ClientRecvTask::initialize(int argc, char** argv)
{ }

/*
 * Receive a packet from clients via sensor netwwork
 * and generate a event to execute the packet handling  procedure
 * of MQTTSNPacketHandlingTask.
 */

void ClientRecvTask::run( ) {
	ClientList* clientList;
	EventQue* packetEventQue;
	bool isAggrActive;
	Event* ev;
	AdapterManager* adpMgr;
	QoSm1Proxy* qosm1Proxy;
	Forwarder* fwd;
	Client* client;
	ev = nullptr;
	adpMgr = _gateway->getAdapterManager();
	qosm1Proxy = adpMgr->getQoSm1Proxy();
	isAggrActive = adpMgr->isAggregaterActive();
	clientList = _gateway->getClientList();		// it will pass &Client_List[0] to clientlist 	
	packetEventQue = _gateway->getPacketEventQue();
	fwd = nullptr;
	client = nullptr;
	MQTTSNPacket* packet;
	char buf[128];
	int rc; 
	int dtls_timeout = 10;
	int chat_timeout = 20;
	unsigned char* PBuf;
	int PBufLen;
	uint8_t rcvbuf[MQTTSNGW_MAX_PACKET_SIZE];
	int len;
	clientList->print_list();
	
	while(1) {
		WirelessNodeId nodeId;
		packet = (MQTTSNPacket*) malloc (sizeof(MQTTSNPacket));
		packet = new MQTTSNPacket();
		PBuf = packet->getbuf(); // Added
		PBufLen = packet->getbufLen(); 	// Added
		len = _sensorNetwork->read(ssl, (uint8_t*) rcvbuf, MQTTSNGW_MAX_PACKET_SIZE);
		
		if (len > 1) {
			if ( PBuf ) {
				free(PBuf);
			}

			PBuf = (unsigned char*)calloc(len, sizeof(unsigned char));
			if ( PBuf ) {
				memcpy(PBuf, rcvbuf, len);
				PBufLen = len;
			}
			else {
				PBufLen = 0;
			}
		}
		else {
			len = 0;
		}
		
		packet->setbuf(PBuf);
		packet->setbufLen(len);
		
		MQTTSNPacket* temp = packet;

		_sensorNetwork->getSenderAddress()->setAddress(addr.sin_addr.s_addr, addr.sin_port);

		//int packetLen;  
		//packetLen = packet->recv(_sensorNetwork, ssl);
		
		// Catch the exeption 'CTRL + C' and exit 
		if (CHK_SIGINT){
			_gateway->setFlag();
			WRITELOG("%s ClientRecvTask   stopped.\n", currentDateTime());
			delete packet;
			return;
		}

		//if (packetLen < 2 ) {
		if (len < 2 ) {
			delete packet;
			continue;
		}

		if ( packet->getType() <= MQTTSN_ADVERTISE || packet->getType() == MQTTSN_GWINFO ) {
			delete packet;
			continue;
		}

		if ( packet->getType() == MQTTSN_SEARCHGW ) {
			/* write log and post Event */
			log(0, packet, 0);
			ev = new Event();
			ev->setBrodcastEvent(packet);
			packetEventQue->post(ev);
			continue;
		}

		SensorNetAddress* senderAddr = _gateway->getSensorNetwork()->getSenderAddress();

		if ( packet->getType() == MQTTSN_ENCAPSULATED ) {
			fwd = _gateway->getAdapterManager()->getForwarderList()->getForwarder(senderAddr);

			if ( fwd != nullptr ) {
				MQTTSNString fwdName = MQTTSNString_initializer;
				fwdName.cstring = const_cast<char *>( fwd->getName() );
				log(0, packet, &fwdName);
				/* get the packet from the encapsulation message */
				MQTTSNGWEncapsulatedPacket  encap;
				encap.desirialize(packet->getPacketData(), packet->getPacketLength());
				nodeId.setId( encap.getWirelessNodeId() );
				client = fwd->getClient(&nodeId);
				packet = encap.getMQTTSNPacket();
			}
		}
		else {
			/*   Check the client belonging to QoS-1Proxy  ?    */

			if ( qosm1Proxy->isActive() ) {
				 const char* clientName = qosm1Proxy->getClientId(senderAddr);

				if ( clientName ) {
					if ( !packet->isQoSMinusPUBLISH() ) {
						client = qosm1Proxy->getClient();
						log(clientName, packet);
						WRITELOG("%s %s  %s can send only PUBLISH with QoS-1.%s\n", ERRMSG_HEADER, clientName, senderAddr->sprint(buf), ERRMSG_FOOTER);
						delete packet;
						continue;
					}
				}
			}
		}

		client = _gateway->getClientList()->getClient(senderAddr);

		if ( client ) {
			log(client, packet, 0);
			
			ev = new Event();
			ev->setClientRecvEvent(client,packet);
			packetEventQue->post(ev);
		}
		else {
			/* new client */
 		    if (packet->getType() == MQTTSN_CONNECT) {
				MQTTSNPacket_connectData data;
				memset(&data, 0, sizeof(MQTTSNPacket_connectData));
				if ( !packet->getCONNECT(&data) ) {
					log(0, packet, &data.clientID);
					WRITELOG("%s CONNECT message form %s is incorrect.%s\n", ERRMSG_HEADER, senderAddr->sprint(buf), ERRMSG_FOOTER);
					delete packet;
					continue;
		 		}
				
				client = clientList->getClient(&data.clientID);
				
				if ( fwd ) {
				    if ( client == nullptr ) {
				        client = clientList->createClient2(0, &data.clientID, isAggrActive, ssl, _tid);
				    }
				    /* Add to af forwarded client list of forwarder. */
                    fwd->addClient(client, &nodeId);
				}
				else {
                    if ( client ) {
			client->setClientAddress(senderAddr);
			client->setClientSSL(ssl);
                    }
                    else {
                        client = clientList->createClient2(senderAddr, &data.clientID, isAggrActive, ssl, _tid);
                    }
				}

				log(client, packet, &data.clientID);
				if (!client) {
					WRITELOG("%s Client(%s) was rejected. CONNECT message has been discarded.%s\n", ERRMSG_HEADER, senderAddr->sprint(buf), ERRMSG_FOOTER);
					delete packet;
					continue;
				}

				/* post Client RecvEvent */
				ev = new Event();
				ev->setClientRecvEvent(client, packet);
				packetEventQue->post(ev);
			}
 		    else {
				log(client, packet, 0);
				if ( packet->getType() == MQTTSN_ENCAPSULATED ) {
					WRITELOG("%s Forwarder(%s) is not declared by ClientList file. message has been discarded.%s\n", ERRMSG_HEADER, _sensorNetwork->getSenderAddress()->sprint(buf), ERRMSG_FOOTER);
				}
				else {
					WRITELOG("%s Client(%s) is not connecting. message has been discarded.%s\n", ERRMSG_HEADER, senderAddr->sprint(buf), ERRMSG_FOOTER);
				}
				delete packet;
			}
		   clientList->print_list();
		}
		if ( temp->getType() == MQTTSN_DISCONNECT ) {
			_gateway->decrement(); // _threadcount--
			return;
		}
	}
}

/* Chat Module */
void ClientRecvTask::ChatModule() {

} 

void ClientRecvTask::log(Client* client, MQTTSNPacket* packet, MQTTSNString* id)
{
	const char* clientId;
	char cstr[MAX_CLIENTID_LENGTH + 1];

	if ( id )
	{
	    if ( id->cstring )
	    {
	        strncpy(cstr, id->cstring, strlen(id->cstring) );
	        clientId = cstr;
	    }
	    else
	    {
	    memset((void*)cstr, 0, id->lenstring.len + 1);
            strncpy(cstr, id->lenstring.data, id->lenstring.len );
            clientId = cstr; 
	    }
	}
	else if ( client )
	{
		clientId = client->getClientId();
	}
	else
	{
		clientId = UNKNOWNCL;
	}
	log(clientId,  packet);
}

void ClientRecvTask::log(const char* clientId, MQTTSNPacket* packet)
{
    char pbuf[ SIZE_OF_LOG_PACKET * 3 + 1];
    char msgId[6];

    switch (packet->getType())
    {
    case MQTTSN_SEARCHGW:
        WRITELOG(FORMAT_Y_G_G_NL, currentDateTime(), packet->getName(), LEFTARROW, CLIENT, packet->print(pbuf));
        break;
    case MQTTSN_CONNECT:
    case MQTTSN_PINGREQ:
        WRITELOG(FORMAT_Y_G_G_NL, currentDateTime(), packet->getName(), LEFTARROW, clientId, packet->print(pbuf));
        break;
    case MQTTSN_DISCONNECT:
    case MQTTSN_WILLTOPICUPD:
    case MQTTSN_WILLMSGUPD:
    case MQTTSN_WILLTOPIC:
    case MQTTSN_WILLMSG:
        WRITELOG(FORMAT_Y_G_G, currentDateTime(), packet->getName(), LEFTARROW, clientId, packet->print(pbuf));
        break;
    case MQTTSN_PUBLISH:
    case MQTTSN_REGISTER:
    case MQTTSN_SUBSCRIBE:
    case MQTTSN_UNSUBSCRIBE:
        WRITELOG(FORMAT_G_MSGID_G_G_NL, currentDateTime(), packet->getName(), packet->getMsgId(msgId), LEFTARROW, clientId, packet->print(pbuf));
        break;
    case MQTTSN_REGACK:
    case MQTTSN_PUBACK:
    case MQTTSN_PUBREC:
    case MQTTSN_PUBREL:
    case MQTTSN_PUBCOMP:
        WRITELOG(FORMAT_G_MSGID_G_G, currentDateTime(), packet->getName(), packet->getMsgId(msgId), LEFTARROW, clientId, packet->print(pbuf));
        break;
    case MQTTSN_ENCAPSULATED:
            WRITELOG(FORMAT_Y_G_G, currentDateTime(), packet->getName(), LEFTARROW, clientId, packet->print(pbuf));
            break;
    default:
        WRITELOG(FORMAT_W_NL, currentDateTime(), packet->getName(), LEFTARROW, clientId, packet->print(pbuf));
        break;
    }
}
