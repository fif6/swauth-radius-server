#!/bin/bash


SRVIP='127.0.0.1'

LOGIN='10.71.3.112'
PASSWD=$LOGIN

#echo "Framed-Protocol = PPP, User-Name = west, NAS-IP-Address = '1.2.3.4'" | radclient $SRVIP:1812 1 seckey

radtest $LOGIN $PASSWD $SRVIP:1812 555 seckey 1 1.2.3.4

#exit

DATESTART=`date`

for (( count=1; count<2; count++ ))
do
	radtest $LOGIN $PASSWD $SRVIP:1812 555 seckey 1 1.2.3.4
	#echo "$count"
done


echo
echo

echo $DATESTART
echo `date`
