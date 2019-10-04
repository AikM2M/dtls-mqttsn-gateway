/************************************************************************************
 * Contribution:	Condition is added to exit the thread of that client who sends a
 * 					proper DISCONNECT packet
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
#ifndef MQTTSNGWBROKERSENDTASK_H_
#define MQTTSNGWBROKERSENDTASK_H_

#include "MQTTSNGWDefines.h"
#include "MQTTSNGateway.h"
#include "MQTTSNGWClient.h"

namespace MQTTSNGW
{
class Adapter;

/*=====================================
     Class BrokerSendTask
 =====================================*/
class BrokerSendTask : public Thread
{
	MAGIC_WORD_FOR_THREAD;
	friend AdapterManager;
public:
	BrokerSendTask(Gateway* gateway);
	~BrokerSendTask();
	void initialize(int argc, char** argv);
	void run();
private:
	void log(Client*, MQTTGWPacket*);
	Gateway* _gateway;
	GatewayParams* _gwparams;
	LightIndicator* _light;
};

}
#endif /* MQTTSNGWBROKERSENDTASK_H_ */
