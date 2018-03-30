#!/bin/bash

# check in anti-theft script
# psuedo -
#		check who am i					[ assume guest account used as not pw protected ]
#			'-- if user 'guest'
#					'- SUSPECT =1			[ suspicious(tm) ]
#			' if suspect = 1			[ check batsignal ]
#					'-- check BATSIGNAL
#				if BATSIGNAL = 1		[ batsignal confirms theft ]
#					'-- RESPOND = 1'	[ begin response ]
#				if respond = 1			[ send DATA every time internet connection is available ]
#					'-- Gather DATA		[ begin to analyse surroundings ]
#					'-- mail or post DATA to myself.		[ send data - look into securing? ]
#					'-- DAYS_MISSING ++ 								[ gets more intrusive longer it's listening ]
#				if DAYS_MISSING > THRESHOLD						[ after threshold attempt to dial out by ]
#					'-- begin COUNTERMEASURES						[ ANY MEANS NECCESARY ]
#
# 	Assumes user running a static address server. Server must provide a configurable status page
# 	and logging capability. Personal - ideally run a small python HTTP server, IP chains to drop any packet
#		without the custom useragent (seems like an easy filter?) set. Doesn't have to be complicated.
#		todo - learn internet.
#		Page1 : GET returns bare page with status 1 or 0 (configurable)
#		Page2 : POST form, submit details of location to this page.
#
#		Useful data to send - External IP, ESSID, geolocation...
#		Geolocation not reliable. Phone-home/shell capability would be nice? 7
#
#
#		MyFirstBashCode  - be gentle




UNAME="notroot"
IFACE="wlan0"
CAVE_FILE="/etc/ch_sh/cave"
R_FILE="/etc/ch_sh/response"			# Response file
S_FILE="/etc/ch_sh/status"				# Status file
LOG_FILE="/var/log/check_in"			# log file
SA="10.0.0.1"   									# server address

CONN_STATUS=4

check_routes(){
		#check for basic routes, sets CONN_STATUS 0-5
		GATEWAY=$(route | grep default | awk '{$1=$1};1' | cut -f2 -d" ")
		IP=$(ifconfig wlp9s0 | grep "inet addr" | awk '{$1=$1;}1' | cut -d" " -f2 | cut -d":" -f2)
		if [ -z $GATEWAY ] && [ -z $IP ]; then	# -z 0 length string
			log "NOT ONLINE"											# no address or gateway
			CONN_STATUS=3
			return 																# no route/addr assigned
		else																		# route available
			L="PINGING 8.8.8.8 FROM "$IP
			ping -c 3 8.8.8.8 &>/dev/null					# ping test
			if [ $? == 1 ]; then									# ping fails
				L=$L" - FAILED TO CONNECT"					# add log
				ping -c 3 -t 10 $GATEWAY)						# try pinging gateway
				if [ $? == 1 ]; then								# gate ping fails
					L=$L" and Failed to Ping Gateway"	# log it
					CONN_STATUS=2 										# unable to ping gateway
					log $L
					return														# back
				else
					L=$L" but Gateway ping succeeded"	# able to ping a gateway, not able to get online
					CONN_STATUS=1											# i.e portal - can do some tricks tho. See SammyK's ICMP tunnel
					log $L
					return
				fi
			else																	# online
			 	CONN_STATUS=0												# set global
				L=$L" + SUCCESFULL "								# there's probably better ways of logging than this
				log $L
				return
		fi
}

log(){
		# log some data and a date-a
		L_DATA=$(date)":"$1											# date:log_info format
		echo $L_DATA >> $LOG_FILE 2&>/dev/null	# echo to file
		if $L_COUNT > 1000; then								# 1k entries per log file
			L_COUNT=0															# reset logcounter
			FILENAME=$(date +"%d%m%y_chsh_log")		# datestamp for the log
			cp $LOG_FILE /var/log/ch_sh/$FILENAME	# copy to old log file
			gzip /var/log/ch_sh/$FILENAME					# zip it up
			echo " " > $LOG_FILE									# clear the active log
		fi
		let L_COUNT+=1													# L ++
}

check_user(){
		USER=$(whoami)
		if [ $USER == "guest" ]; then
			echo "1" > $S_FILE
		fi
}

ping_check(){
	# OLD METHOD - redone
	while [ $ONLINE != 1 ]; do						# works with 1 OR 2 sets of test brackets!
		nc -z -w3 8.8.8.8 53 2&>/dev/null		# Use 1 for better portability ( thanks, SO!)
		if [ $0 -eq 0 ]; then
	    		ONLINE=1
		else
	    		ONLINE=0
		fi;

	sleep 100
	done

}



seeme(){
	get_details														# get local details
	E_DATA=$(echo $DATA | base64 -w 0 -)	# encrypt a little for transport (base64 isn't encryption, nub.)
	curl --retry 5 -A "check_in_sh" -G -d $E_DATA $SA 	# set UAGENT check_in_sh, send get to dialback (ALARM SIG)

}

checkSig(){
	SIG=$(curl --retry 5 -A "check_in_sh" -G $BA) #| grep BAT | cut -d"=" -f2) something like this - refine w. page
	if [ $SIG == '1' ]; then							# IF BATSIGNAL == STOLEN
		echo 1 > $R_FILE										# shit's going down, set flags
		R_FLAG=1
		L="[!] BATSIGNAL ACTIVATED! GOING TO R MODE [!]"
	elif [ $SIG == '0' ]; then						# Don't want to stop checking if Batsignal not on 1st time
		L="[+] BATSIGNAL NORMAL "
		return															# Just stay in the background, checking every now and then
	else
		L="Error getting BatSignal"
	log $L
}

get_details(){
	# get details of network
	IP=$(ifconfig $IFACE | grep "inet addr" | awk '{$1=$1;}1' | cut -d" " -f2 | cut -d":" -f2)
	EXTERNAL_IP=$(dig +short myip.opendns.com @resolver1.opendns.com)
	GEOLOC=$(curl -s ipinfo.io/$EXTERNAL_IP | grep loc | cut -f4 -d " " | sed 's/"//g')
	GATEWAY=$(route | grep default | awk '{$1=$1};1' | cut -f2 -d" ")
	NET_ESSID=$(iwconfig $IFACE | grep ESSID | cut -d":" -f2 | sed 's/\"//g' | sed 's/\ /\_/g')
	DATA=$IP":"$EXTERNAL_IP":"$GEOLOC":"$GATEWAY":"$NET_ESSID
}


alert_mode(){
	# alert mode watches internet status and connects to batsignal if possible
	# if not possible then attempts to poll/scan enviro?
	# using multiple different 'levels' of 'connectedness' to give best chance of reaching out
	#	Do basic connected/Not-connected first then add more later...
	CONN_STATUS=5
	while [ $CONN_STATUS -ne 0  ]; do		# keep checking routes until something happens
		sleep 100													# TODO add cases for less than full-connect
		check_routes
	case CONN_STATUS in
		0 )																# connected to the internet
		checkSig													# chk signal and send info to server
			;;
		#1 )															# able to ping gateway but not online, fw/portal? Do later
		#something
			;;
		#2 )
		#somethingelse
		#	;;
	esac
}


srs_mode(){
	# srs mode occurs when batsignal has been confirmed and encompasses active attempts to
	# retrieve information
	check_routes
	if [ CONN_STATUS == 0 ]; then
		helpme						# if connected, beacon information
	else
		while [ CONN_STATUS != 0 ]; do		# else keep trying for connection
			check_routes
			sleep 200
		  let SCREAM+=1										# threshhold for additional action
			if [ $SCREAM > 1000 ]; then
				rage
		done
}


### MAIN ###
# read flags from file (@startup), set flags as appropriate
# S  = suspect flag : someone has logged into computer on guest account - check further!
# R  = red flag : Theft has been confirmed, actions will be taken.

if [ -f $S_FILE ] && [ -f $R_FILE ]; then			# check files exist
	ST=$(cat $S_FILE)												# cat files to flags
	RT=$(cat $R_FILE)
else																			# if no files, make files
	echo "0" > $S_FILE											# first time run
	echo "0" > $R_FILE											# first time run
fi

if [ $ST != "0" ]; then										# CHECK 1 : if suspect file is set, set FLAG
	S_FLAG=1
else if [ $(whoami) != $UNAME ]; then			# else if user not main account
	S_FLAG=1																# set flag
else																			# else flag off
	S_FLAG=0
if [ $RT != "0" ]; then										# CHECK 2: R_flag from file
	R_FLAG=1


if [ $R_FLAG ]; then											# Stolen, srs mode.
	srs_mode																# srs mode continuous retrieval efforts
else if [ $S_FLAG ]; then
	alert_mode															# suspect, check further (see batsignal info)
else
	exit																		# all flags ok and logged in as user, exit.
