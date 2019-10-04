/************************************************************************************
 * Contribution:	Additional functions are implemented to add information of SSI 
 *                  and thread-id is added into the existing structure
 *                  'MQTTSNGWClientList'
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
 *    Tieto Poland Sp. z o.o. - Gateway improvements
 **************************************************************************************/

#ifndef MQTTSNGATEWAY_SRC_MQTTSNGWCLIENTLIST_H_
#define MQTTSNGATEWAY_SRC_MQTTSNGWCLIENTLIST_H_

#include "MQTTSNGWClient.h"
#include "MQTTSNGateway.h"

namespace MQTTSNGW
{
#define TRANSPEARENT_TYPE 0
#define QOSM1PROXY_TYPE 1
#define AGGREGATER_TYPE 2
#define FORWARDER_TYPE  3

class Client;

/*=====================================
 Class ClientList
 =====================================*/
class ClientList
{
public:
    ClientList();
    ~ClientList();

    void initialize(bool aggregate);
    void setClientList(int type);
    void setPredefinedTopics(bool aggregate);
    void erase(Client*&);
    Client* createClient2(SensorNetAddress* addr, MQTTSNString* clientId,int type, SSL* ssl, pthread_t _tid);
    Client* createClient2(SensorNetAddress* addr, MQTTSNString* clientId, bool unstableLine, bool secure, int type, SSL* ssl, pthread_t _tid);

    Client* createClient(SensorNetAddress* addr, MQTTSNString* clientId,int type);
    Client* createClient(SensorNetAddress* addr, MQTTSNString* clientId, bool unstableLine, bool secure, int type);

    bool createList(const char* fileName, int type);
    Client* getClient(SensorNetAddress* addr);
    Client* getClient(MQTTSNString* clientId);
    Client* getClient(int index);
    pthread_t getcltThreadID(MQTTSNString* clientId);
    uint16_t getClientCount(void);
    Client* getClient(void);
    bool isAuthorized();
    int print_list();

private:
    bool readPredefinedList(const char* fileName, bool _aggregate);
    Gateway* _gateway {nullptr};
    Client* createPredefinedTopic( MQTTSNString* clientId, string topicName, uint16_t toipcId, bool _aggregate);
    Client* _firstClient;
    Client* _endClient;
    uint16_t _clientCnt;
    Mutex _mutex;
    bool _authorize {false};
};


}



#endif /* MQTTSNGATEWAY_SRC_MQTTSNGWCLIENTLIST_H_ */
