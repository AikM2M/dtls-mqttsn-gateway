/*
 * README file for DTLS based MQTTSN Gateway Application 
 * Author:	 		TOMOAKI YAMAGUCHI
 * Contributor:	 	BILAL IMRAN @ linkedin.com/in/imranbilal 
 * Contribution: (1) Multi-threaded DTLS over UDP connection support to connect 
 *     		     to MQTTSN Gateway either using Pre-shared Key or Certificates
 *		 (2) Pre-shared Key based TLS over TCP connection to connect to MQTT broker
 */ 
 
/*
 * Discription:
 * The current release of MQTTSN Gateway Application @ https://github.com/eclipse/paho.mqtt-sn.embedded-c.git supports UDP based
 * connection to its mqttsn clients and lags in providing DTLS based security. This new release of DTLS based MQTTSN Application @ supports 
 * Multi-threaded DTLS based connections to its mqttsn clients which uses either Pre-shared Key or the Certificates to connect to 
 * this MQTTSN Gateway. In addition to Certificate based TLS over TCP connection support, a Pre-shared Key based TLS over TCP connection 
 * suppport is also added to ease the mqttsn clients to connect to MQTT broker.
 */ 
 
/*
 * Modes of Connections:
 *  There are currently over five different modes of connection available in MQTTSN Gateway Application such as;
 * (1)	mqttsn client to MQTTSN Gateway server End to End Connections {Connection 01}
 * (2)	MQTTSN Gateway to MQTT broker End to End Connections {Connection 02}
 */
 
/*
 * Connection Setup:
 * The Configuration file of MQTTSN Gateway @ gateway.config01 has multiple plug-ins to run gateway in different modes. The following
 * necessary settings of those plug-ins are shown to enable each connection setup. 
 *  <NOTE: 01> Please follow the setting given below as mentioned for safe connection setup.
 *  <NOTE: 02> Do not run more than one settings at once because it wouldn't work. Proteciton against these settings are added
 *		into the program to make in run in appropriate conditions.
 *  <NOTE: 03> It is highly recommended to do broker setting at 1st. Broker settings could easily be done @ mosquitto.conf file in
 *		the directory to mosquitto broker where it is installed in the system 
 */

/* 
 * Mosquitto Broker Connection Settings @ mosquitto.conf file:
 *
 *	 (1)	Plain TCP Connection Setting:
 *			-> port set to 1883 in Default listener section
 *		<NOTE: 04> Please comment every other option to make this setting work on MQTT broker
 *	
 *  	 (2)	TLS with PSK over TCP Connection Setting:
 *		-> port set to 8883 in Default listener section
 *		-> psk_hint set to "'bridge' (just an example, you can change it)" in Pre-shared-key based SSL/TLS support section
 *		-> allow_anonymous set to 'true' in Security section
 *		-> psk_file set to '/home/pi/Desktop/key_file.txt' directory in Default authentication and topic access control section
 *		the directory  address should be where the keys & IDs are written in a file '.txt' and defined in a format 
 *		e.g: 'bridge:0102030405'
 *		<NOTE: 05> Please comment every other option to make this setting work on MQTT broker
 *
 *	 (3) TLS with Certificate over TCP Connection Setting:
 *		-> port set to 8883 in Default listener section
 *		-> cafile set to the address/CA.crt e.g: /home/pi/Desktop/CA.crt
 *		-> ca path set to the address to the directory where CA.crt is available e.g: /home/pi/Desktop
 *		-> certfile set to the address of server certificate e.g: /home/pi/Dekstop/server.crt
 *		-> keyfile set to the address of server key e.g: /home/pi/Desktop/server.key
 *		-> require_certificate set to 'true'
 *		-> use_subject_as_username set to 'true'
 *		<Note: 06> Please use IP address of the Mosquitto broker in the CN field of the server certificate else it would be rejected by
 *		the paho-mqttsn client written in Mbed OS available @ and handshake will fail
 *		<NOTE: 07> Please comment every other option to make this setting work on MQTT broker
 */ 
 
/*
 * MQTTSN Gateway Connection Settings @ gateway.conf01 file:
 *
 *	 (1) Plain UDP Connection Setting:
 *		This version of MQTTSN Gateway Application @ doesn't provide support to downgrade its connection settings to simple UDP as
 *		the complete focus to this project is to provide means to secure data from mqttsn clients via DTLS over UDP connection but
 *		if you still want to use plain UDP please refer to the previous stable verison of MQTTSN Gateway Application @ 
 *		https://github.com/eclipse/paho.mqtt-sn.embedded-c.git 
 *
 *	 (2) Pre-shared Key based DTLS over UDP Connection Setting:
 *		-> BrokerSecurePortNo set to 8883
 *		-> BrokerName set to IP address of the Mosquitto MQTT Broker
 *		-> DTLSServerName set to the IP address of the MQTTSN Gateway
 *		-> DTLSPortNo set to the desired port number for MQTTSN Gateway DTLS server (6667 by default)
 *		-> DtlsPskEnable set to 'YES'	(Mandatory)
 *		-> DtlsCertEnable set to 'NO'	(Optional)
 *		-> DtlsDebug is optional (if set to 'YES' would debug only Dtls connection) 
 *		<NOTE: 08> Please choose port number other than 1883, 8883 as they are used to connect to the broker
 *		<NOTE: 09> Please set other settings accordingly to make this setting work on MQTTSN Gateway
 *
 *	 (3) Certificate based DTLS over UDP Connection Setting:
 *		-> BrokerSecurePortNo set to 8883
 *		-> BrokerName set to IP address of the Mosquitto MQTT Broker
 *		-> DTLSServerName set to the IP address of the MQTTSN Gateway
 *		-> DTLSPortNo set to the desired port number for MQTTSN Gateway DTLS server (6667 by default)
 *		-> DtlsPskEnable set to 'NO'	(Optional)
 *		-> DtlsCertEnable set to 'YES'	(Mandatory)
 *		-> Dtls_CA_Cert set to the address of the CA.crt for MQTTSN Gateway DTLS Server e.g: /home/pi/Desktop/CA.crt 				(Mandatory)
 *		-> Dtls_Server_Cert set to the address of the Server.crt for MQTTSN Gateway DTLS Server e.g: /home/pi/Desktop/Server.crt 	(Mandatory)
 *		-> Dtls_Server_Key set to the address of the Server.key for MQTTSN Gateway DTLS Server e.g: /home/pi/Desktop/Server.key 	(Mandatory)
 *		-> DtlsDebug is optional (if set to 'YES' would debug only Dtls connection) 
 *		<NOTE: 10> Please choose port number other than 1883, 8883 as they are used to connect to the broker
 *		<NOTE: 11> Please set other settings accordingly to make this setting work on MQTTSN Gateway
 *
 *	 (4) Pre-shared Key based TLS over TCP Connection Settings:
 *		-> BrokerSecurePortNo set to 8883
 *		-> BrokerName set to IP address of the Mosquitto MQTT Broker
 *		-> TlsPskEnable set to 'YES' alongwith Setting (2) & (3)
 *		-> TlsCertEnable set to 'NO' alongwith Setting (2) & (3)
 *		-> TlsDebug is optional (if set to 'YES', would debug the TLS over TCP connection)
 *		<NOTE: 12> Please choose port number other than 1883, 8883 as they are used to connect to the broker
 *		<NOTE: 13> Please set other settings accordingly to make this setting work on MQTTSN Gateway
 *
 *	 (5) Certificate based TLS over TCP Connection Settings:
 *		-> BrokerSecurePortNo set to 8883
 *		-> BrokerName set to IP address of the Mosquitto MQTT Broker
 *		-> TlsPskEnable set to 'NO' alongwith Setting (2) & (3)
 *		-> TlsCertEnable set to 'YES' alongwith Setting (2) & (3)
 *		-> RootCAfile set to the file address of the CA.crt e.g: /home/pi/Desktop/RootCA.crt
 *		-> RootCAPath set to the directory of the CA.crt e.g: /home/pi/Desktop/RootCA.crt
 *		-> CertsFile set to the file address of the Certificate for TLS connection to the broker
 *		-> PrivateKey	set to the file address of the Key for TLS connection to the broker
 *		-> TlsDebug is optional (if set to 'YES', would debug the TLS over TCP connection)
 *		<NOTE: 14> Please choose port number other than 1883, 8883 as they are used to connect to the broker
 *		<NOTE: 15> Please set other settings accordingly to make this setting work on MQTTSN Gateway		
 */