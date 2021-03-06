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
#ifndef MQTTSNGWCLIENTRECVTASK_H_
#define MQTTSNGWCLIENTRECVTASK_H_

#include "SensorNetwork.h"
#include "MQTTSNGateway.h"

namespace MQTTSNGW
{
class AdapterManager;

/*=====================================
     Class ClientRecvTask
 =====================================*/
class ClientRecvTask:public Thread
{
	MAGIC_WORD_FOR_THREAD;
	friend AdapterManager;
public:
	ClientRecvTask() {};

	ClientRecvTask(Gateway*);
	~ClientRecvTask(void);
	virtual void initialize(int argc, char** argv);
	void run();
	void ChatModule ();
	
	SensorNetwork* getSN();
	void setGW(Gateway* gw) {_gateway = gw;};
	Gateway* getGW() {return _gateway;};
	SSL *ssl;
	sockaddr_in addr;
	pthread_t _tid;

private:
	void log(Client*, MQTTSNPacket*, MQTTSNString* id);
	void log(const char* clientId, MQTTSNPacket* packet);

	Gateway*       _gateway;
	SensorNetwork* _sensorNetwork;
};

}

#endif /* MQTTSNGWCLIENTRECVTASK_H_ */
