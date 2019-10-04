# dtls-mqttsngateway
## Main Features
* Multi-threaded DTLS over UDP connection modes supported for mqttsn clients 
    * DTLS with PSK
    * DTLS with Certificate
* TLS over TCP connection support for MQTTSN Gateway to connect to Broker
    * TLS with PSK 
    * TLS with Certificate 
## Project Description
The current release of MQTTSN Gateway Application @ https://github.com/eclipse/paho.mqtt-sn.embedded-c.git supports UDP based
connections for its mqttsn clients and lags in providing DTLS based security. This new release of DTLS based Multi-Threaded MQTTSN Gateway Application @ https://github.com/onem2m-iril1/dtls-mqttsngateway.git supports Multi-threaded DTLS based connections to its mqttsn clients which use either Pre-shared Keys or Certificates to connect to respective MQTTSN Gateway. In addition to Certificate based TLS over TCP connection support, a Pre-shared Key based TLS over TCP connection suppport is also provided to facilitate the connectivity of gateway to MQTT broker.
## Dependencies
* git
```
$ sudo apt-get update
$ sudo apt-get install git
```
* libssl-dev
```
$ sudo apt-get install libssl-dev
```
* make 
```
$ sudo apt-get update
$ sudo apt-get install make
```
* c++
```
$ sudo apt-get install g++
```
* MQTT Broker
```
$ sudo apt-get install mosquitto
```
## Clone
```
$ git clone -b brach_name project_url.git
```
## Connection Setup
The Configuration file of MQTTSN Gateway in installed_directory/dtls-mqttsngateway/gateway.config01 has multiple plug-ins to run gateway in different modes. The following necessary settings of those plug-ins are shown to enable each connection setup. 
* <NOTE: 01> Please follow the settings given in the next section for secure connection setup.
* <NOTE: 02> Do not run more than one settings at once because it wouldn't work.
* <NOTE: 03> It is highly recommended to configure Broker first using mosquitto.conf file which can be easily found in installed directory. 

## Mosquitto Broker Connection Settings in mosquitto/mosquitto.conf file:
* Plain TCP Connection Settings:
   * set 'port' to '1883' in 'Default listener' section.
   * <NOTE: 04> Please comment every other option to make these setting work on MQTT broker.
* TLS with PSK over TCP Connection Setting:
   * set 'port' to '8883' in 'Default listener' section
   * set 'psk_hint' to 'bridge' (as an example) in 'Pre-shared-key based SSL/TLS support' section
   * set 'allow_anonymous' to 'true' in 'Security' section
   * set 'psk_file' to '/home/pi/Desktop/key_file.txt' (as an example) in 'Default authentication and topic access control' section.
   * <Note: 05> The directory should be where the keys & IDs are written in a file '.txt' and defined in a format e.g:           'bridge:0102030405'
   * <NOTE: 06> Please comment every other option to make this setting work on MQTT broker
* TLS with Certificate over TCP Connection Settings:
   * set 'port' to '8883' in 'Default listener' section
   * set 'cafile' to the 'address/CA.crt' e.g: /home/pi/Desktop/CA.crt (as an example)
   * set 'capath' to the address to the directory where CA.crt is available e.g: /home/pi/Desktop (as an example)
   * set 'certfile' to the address of server certificate e.g: /home/pi/Dekstop/server.crt (as an example)
   * set 'keyfile' to the address of server key e.g: /home/pi/Desktop/server.key (as an example)
   * set 'require_certificate' to 'true'.
   * set 'use_subject_as_username' to 'true'.
   * <Note: 07> Please use IP address of the Mosquitto Broker in the CN field of the server certificate else it would be rejected by the paho-mqttsn client written in Mbed OS available @ and the handshake will fail.
   * <NOTE: 08> Please comment every other option to make these setting work on MQTT Broker.

## Gateway Connection Settings in gateway.conf01 file:
* Plain UDP Connection Setting:
   * This version of MQTTSN Gateway Application @ https://github.com/onem2m-iril1/dtls-mqttsngateway.git doesn't provide support to downgrade its connection settings to simple UDP as the complete focus to this project is to provide means to secure data from mqttsn clients via DTLS over UDP connection but if you still want to use plain UDP please refer to the previous stable verison of MQTTSN Gateway Application @ https://github.com/eclipse/paho.mqttsn.embedded-c.git 
* Pre-shared Key based DTLS over UDP Connection Settings:
   * 'BrokerSecurePortNo' set to '8883'
   * 'BrokerName' set to IP address of the Mosquitto MQTT Broker
   * set 'DTLSServerName' set to the IP address of the MQTTSN Gateway
   * set 'DTLSPortNo' set to the desired port number for MQTTSN Gateway DTLS server (6667 by default)
   * set 'DtlsPskEnable' set to 'YES'	(Mandatory)
   * set 'DtlsCertEnable' set to 'NO'	(Optional)
   * set 'DtlsDebug' is optional (if set to 'YES' would debug only Dtls connection)
   * Update 'Pre-Shared Key LookUP Table' with identities and associated key values for individual mqtt-sn clients. It is defined in 'mainGateway.cpp' line 84.
   * <NOTE: 08> Please choose port number other than 1883, 8883 as they are assigned to the broker
   * <NOTE: 10> Pre-Shared Key values are supposed to be defined in hex format
* Certificate based DTLS over UDP Connection Settings:
   * set 'BrokerSecurePortNo' to '8883'
   * set 'BrokerName' set to IP address of the Mosquitto MQTT Broker
   * set 'DTLSServerName' to the IP address of the MQTTSN Gateway
   * set 'DTLSPortNo' to the desired port number for MQTTSN Gateway DTLS server (6667 by default)
   * set 'DtlsPskEnable' to 'NO'	(Optional)
   * set 'DtlsCertEnable' to 'YES'	(Mandatory)
   * set 'DtlsCACertFile' to the file address of the CA.crt for MQTTSN Gateway DTLS Server e.g: /home/pi/Desktop/CA.crt (Mandatory)
   * set 'DtlsCACertPath' to the directory of the CA.crt for MQTTSN Gateway DTLS Server e.g: /home/pi/Desktop/   
   * set 'DtlsServerCert' to the address of the Server.crt for MQTTSN Gateway DTLS Server e.g: /home/pi/Desktop/Server.crt (Mandatory)
   * set 'DtlsServerKey' to the address of the Server.key for MQTTSN Gateway DTLS Server e.g: /home/pi/Desktop/Server.key 	(Mandatory)
   * 'DtlsDebug' is optional (if set to 'YES' would debug only Dtls connection) 
   * <NOTE: 11> Please choose port number other than 1883, 8883 as they are used to connect to the broker
   * <NOTE: 12> Please set other settings accordingly to make this setting work on MQTTSN Gateway
* Pre-shared Key based TLS over TCP Connection Settings:
   * set 'BrokerSecurePortNo' set to '8883'
   * set 'BrokerName' to IP address of the Mosquitto MQTT Broker
   * set 'TlsPskEnable' to 'YES' alongwith Setting (2) & (3)
   * set 'TlsCertEnable' to 'NO' alongwith Setting (2) & (3)
   * set 'TlsDebug' is optional (if set to 'YES', would debug the TLS over TCP connection)
   * set 'pskID_client' to the desired identity to be used for gateway to connect to MQTT broker. It is defined in '.../MQTTSNGateway/src/linux/Network.cpp' line 31
   * set 'pskKey_client' to the desired key value to be used for gateway to connect to MQTT broker. It is defined in '.../MQTTSNGateway/src/linux/Network.cpp' line 32
   * <NOTE: 13> Please choose port number other than 1883, 8883 as they are used to connect to the broker
   * <NOTE: 14> Please set other settings accordingly to make this setting work on MQTTSN Gateway
   * <NOTE: 15> Please update the Pre-Shared Key file on MQTT broker side accordingly
* Certificate based TLS over TCP Connection Settings:
   * set 'BrokerSecurePortNo' set to '8883'
   * set 'BrokerName' set to IP address of the Mosquitto MQTT Broker
   * set 'TlsPskEnable' set to 'NO' alongwith Setting (2) & (3)
   * set 'TlsCertEnable' set to 'YES' alongwith Setting (2) & (3)
   * set 'RootCAfile' to the file address of the CA.crt e.g: /home/pi/Desktop/RootCA.crt
   * set 'RootCAPath' set to the directory of the CA.crt e.g: /home/pi/Desktop/RootCA.crt
   * set 'CertsFile' set to the file address of the Certificate for TLS connection to the broker
   * set 'PrivateKey'	set to the file address of the Key for TLS connection to the broker
   * 'TlsDebug' is optional (if set to 'YES', would debug the TLS over TCP connection)
   * <NOTE: 16> Please choose port number other than 1883, 8883 as they are used to connect to the broker
   * <NOTE: 17> Please set other settings accordingly to make this setting work on MQTTSN Gateway	
## Make
```
$ make 
```
## Install
```
$ make install
```
## Clean
```
$ make clean
```
## Run
```
$ ./MQTTSNGateway -f gateway.conf01
```
## Hardware Tested
* Tested on RaspberryPi-2 running RaspbianOS (Jessie Version) 
* Tested with NUCLEO-L476RG mqttsn-client @ running Mbed-OS and using paho-mqtt-sn library. 
## Thread Exit Procedures
   * Thread close/exit procedure is added in case if mqtt-sn client sends a DISCONNECT packet
   * Thread close/exit procedure is to be added in case if mqtt-sn client, for some reason, disconnect without even sending a proper DISCONNECT packet
   * Disconnected client is deleted/erased from the existing Client List
## Author
- TOMOAKI YAMAGUCHI
## Contributor 
- BILAL IMRAN
## oneM2M Project Funding Agency
- National Centre for Cyber Security (NCCS) HEC Gov. Pakistan
## oneM2M Team 
- Internet of Things Research & Innovation Lab (IRIL) KICS UET Lahore, Pakistan
## Team Members
- Dr. Ghalib A. Shah (Principal Investigator)
- Dr. Ali Hammad Akbar (Co-Principal Investigator)
- Bilal Afzal (Previous Team Leader)
- Muhammad Ahsan (Team Leader)
- Bilal Imran (Sr. Research Officer)
- Muhammad Rehan (Research Officer)
- Asim Tanwir (Research Officer)
