#!/usr/bin/perl -w

BEGIN {
	use FindBin;
	unshift(@INC, "${FindBin::RealBin}/modules"); # add custom Modules path at the first of position in @INC
};


use strict;
use warnings;
use POSIX qw(strftime setsid);
use Cwd qw(abs_path);
use Switch;
use Socket;
use IO::Socket::INET;
use Net::Radius::Packet;
use Net::Radius::Dictionary;
#use Data::Dumper; # print Dumper(\@INC);

our $userconf = {};
require $FindBin::RealBin.'/users.conf';



use constant DAEMON_MODE	=> 1; # 0 - Off, 1 - ON
use constant LOG_STDOUT		=> 1; # 0 - Off, 1 - ON
use constant PID_FILE		=> '/var/run/swauth_radius_server.pid';
use constant LOG_FILE		=> '/var/log/swauth_radius_server.log';

use constant BIND_ADDR		=> '1.2.3.4';
use constant BIND_PORT		=> 1812;
use constant SERVER_SECRET	=> 'servsec';
use constant DICTIONARY_FILE	=> $FindBin::RealBin.'/raddb/dictionary';

use constant RSYSLOG_ENABLE		=> 1; # 0 - Off, 1 - ON
use constant RSYSLOG_SERVER		=> '4.3.2.1';
use constant RSYSLOG_SERVER_PORT	=> 514;

my $rsyslog = undef;
if ( RSYSLOG_ENABLE ) {
	use Net::Syslog;
	$rsyslog = Net::Syslog->new('Name' => 'swauth_radius_server', 'Facility' => 'daemon', 'Priority' => 'info', 'SyslogHost' => RSYSLOG_SERVER, 'SyslogPort' => RSYSLOG_SERVER_PORT, 'rfc3164' => 1 );
}



# Unbuffer output
$| = 1;

# for subroutine scope
my $RUNNING = 1;
my ($SOCKET_RCV);

sub signal_handler { # exit signal received. Stopping threads from main process
	logger("INFO: TERMINATE signal catched. Shutting down jobs!");
	$RUNNING = 0;
	close($SOCKET_RCV) if $SOCKET_RCV;
}

sub norm_exit($) {
	#print "Socket alive\n" if $SOCKET_RCV;
	close($SOCKET_RCV) if $SOCKET_RCV;

	unlink(PID_FILE) || print "ERROR: Can't remove PID file '".PID_FILE."' on exit: $!\n";
	print "Terminated\n";
	exit($_[0]);
}

sub logger($) {
	if ( !open(MYLOG, ">> ".LOG_FILE) ) {
		print "ERROR: Log file '".LOG_FILE."' write error: $!";
		norm_exit(254);
	}
	my $curr_time = strftime("%d/%m/%y %H:%M:%S", localtime);
	if ( LOG_STDOUT ) { print STDOUT "[$curr_time] ". $_[0] ."\n"; }
	print(MYLOG "[$curr_time] ". $_[0] ."\n");
	close(MYLOG);
#	if ( RSYSLOG_ENABLE ) {
#		$rsyslog->send( 'Message to be sent to remote syslog server' , Priority => 'info');
#	}
}

sub send_reply ($$$$$){
	my $socket = $_[0];
	my $toaddr = $_[1];
	my $rad_req = $_[2];
	my $rad_resp = $_[3];
	my $rad_serv_secret = $_[4];

	my ($to_port, $to_ip) = unpack_sockaddr_in($toaddr);
	$to_ip = inet_ntoa($to_ip);

	my $resp_udp_pkt = auth_resp($rad_resp->pack, $rad_serv_secret);

#	logger("Sending response ". $rad_resp->code ." to $to_ip:$to_port for User-Name ". $rad_req->attr('User-Name') .", "
#	. ( defined($rad_req->attr('NAS-Identifier')) ? "NAS-Identifier ".$rad_req->attr('NAS-Identifier') : "NAS-IP-Address ".$rad_req->attr('NAS-IP-Address') ) );
	#$rad_resp->dump;
	send($socket, $resp_udp_pkt, 0, $toaddr) || logger("ERROR: Reply UDP packet send error: $!");
}


# -------- Only check and read PID file
my $pid = 0;
if ( -e PID_FILE ) {
	print "WARN: PID file exists.\n";
	open(PIDF, PID_FILE); # opening for read only
	$pid = <PIDF>;
	close(PIDF);
}

if ( $pid && -e "/proc/$pid/stat" ) { # Is proccess number already running by OS KERNEL
	print "ERROR: My process is already exists (PID $pid). Exiting.\n";
	exit(254);
}
# ---

#print "Manual exiting..";
#exit(0);

# -------- Catch terminate signals
$SIG{INT} = $SIG{TERM} = $SIG{HUP} = \&signal_handler;
$SIG{PIPE} = 'IGNORE';

# -------- Create PID file
if ( !open(PIDNF, ">".PID_FILE) ) {
	logger("ERROR: PID file '".PID_FILE."' write error: $!");
	norm_exit(254);
}
print(PIDNF "$$"); # write in to file current PID
close(PIDNF);
# ---

unless ( -r DICTIONARY_FILE ) {
	logger("ERROR: Can't read RADIUS dictionary '". DICTIONARY_FILE ."': $!");
	norm_exit(254);
}
my $rad_dict = new Net::Radius::Dictionary( DICTIONARY_FILE );

# open listening socket
if ( !socket($SOCKET_RCV, PF_INET, SOCK_DGRAM, getprotobyname('udp')) ) {
	logger("ERROR: Socket creation: $!");
	norm_exit(254);
}

if ( !bind($SOCKET_RCV, sockaddr_in(BIND_PORT, inet_aton(BIND_ADDR))) ) {
	logger("ERROR: Can't bind socket to '". BIND_ADDR .":". BIND_PORT ."': $!");
	norm_exit(254);
}


logger("STARTED script: '". abs_path($0) ."', BIND_ADDR: ".BIND_ADDR.", PORT: ".BIND_PORT.", PID_FILE: '".PID_FILE."'");

if ( DAEMON_MODE == 1 ) {
	logger("INFO: Conf DAEMON_MODE=1. Entering Daemon mode.");

	delete @ENV{qw(IFS CDPATH ENV BASH_ENV)}; # Make %ENV safer
	open(STDIN,  "+>/dev/null") or die "Can't open STDIN: $!\n";
	open(STDOUT, "+>&STDIN") or die "Can't open STDOUT: $!\n";
	open(STDERR, "+>&STDIN") or die "Can't open STDERR: $!\n";
	defined(my $tm = fork)  or die "Can't fork script proccess: $!\n";
	exit(254) if $tm;
	setsid() or die "Can't start a new session: $!\n";
	umask 0;
	# ---- Updating PID_FILE with new PID
	if ( !open(PIDNF, ">".PID_FILE) ) {
		logger("ERROR: PID file '".PID_FILE."' write error after daemonizing: $!");
		norm_exit(254);
	}
	print(PIDNF "$$"); # write in to file current PID
	close(PIDNF);
	logger("INFO: New PID is $$");
}


# Loop forever, recieving packets and replying to them
my ($recv_udp_pkt, $recv_udp_from_addr, $recv_udp_from_ip, $recv_udp_from_port, $rad_req, $rad_resp);
my ($privlev);
#my ($sth, $data, $qUser_Name, $db_aid, $qAcct_Session_Id, $qNAS_IP_Address);
#my ($Dbps, $Ubps, $Dburst, $Uburst);


while ($RUNNING == 1) {
	$recv_udp_pkt = undef;
	$recv_udp_from_addr = undef;
	$rad_req = undef;
	$rad_resp = undef;
	$privlev = undef;
	#$sth = undef;
	#$data = undef;
	#$qUser_Name = undef;
	#$db_aid = undef;

	$recv_udp_from_addr = recv($SOCKET_RCV, $recv_udp_pkt, 1500, 0) || logger("ERROR: UDP packet recv err: $!");
	if ( $RUNNING == 0 ) {
		logger("Terminating.\n");
		norm_exit(0);
	}
	#sleep(1);

	($recv_udp_from_port, $recv_udp_from_ip) = unpack_sockaddr_in($recv_udp_from_addr);
	$recv_udp_from_ip = inet_ntoa($recv_udp_from_ip);

	# filter to small packets
	if ( length($recv_udp_pkt) < 20 ) {
		logger("WARN: Received to small UDP packet! From $recv_udp_from_ip:$recv_udp_from_port, length=".length($recv_udp_pkt)."b");
		next;
	}
	

	# ! need to check this code:
	#if (!Net::Radius::Packet::auth_acct_verify($data, $cfg{coa_secret})) {
	#	logger("err", "Host $ipaddr send incorrect authenticator (check secret), ignore packet");
	#	next;
	#}

	# Unpack it
	$rad_req = new Net::Radius::Packet $rad_dict, $recv_udp_pkt;

	if ( !defined($rad_req->code) ) {
		# It's not an Access-Request
		logger("WARN: Undefined packet CODE recieved from $recv_udp_from_ip:$recv_udp_from_port.");
		next;
	}

	if ( $rad_req->code ne 'Access-Request' ) {
		# It's not an Access-Request
		logger("WARN: Unexpected packet CODE '". $rad_req->code ."' recieved from $recv_udp_from_ip:$recv_udp_from_port.");
		next;
	}

	if ( !defined($rad_req->attr('User-Name')) ) {
		logger("WARN: Attribute 'User-Name' is not defined in a request message from $recv_udp_from_ip:$recv_udp_from_port");
		next;
	}


	#if ( $rad_req->attr('User-Name') ne $rad_req->password(SERVER_SECRET) ) {
	#	logger("WARN: Attributes 'User-Name' <=> 'Password' mismatch for SW auth. Check Client-Server SECRET identity");
	#	next;
	#}
	# OK! Its Cisco ISG Access-Request
	#$rad_req->dump;

	logger( "Access-Request from: NAS-IP-Address '".$rad_req->attr('NAS-IP-Address')."', NAS-Identifier '".$rad_req->attr('NAS-Identifier')."', User-Name '".$rad_req->attr('User-Name')."', User-Password '".$rad_req->password(SERVER_SECRET)."'" );

	$rad_resp = new Net::Radius::Packet($rad_dict);

	$rad_resp->set_identifier($rad_req->identifier);
	$rad_resp->set_authenticator($rad_req->authenticator);


	if ( !exists $userconf->{$rad_req->attr('User-Name')} ) {
		# USER NOT FOUND
		logger("Auth-FAIL: No any CONFIG data for User-Name '".$rad_req->attr('User-Name')."', remote host ".$rad_req->attr('NAS-IP-Address') );
#		if ( RSYSLOG_ENABLE ) {
#			$rsyslog->send("Auth-FAIL: No any CONFIG data for User-Name '".$rad_req->attr('User-Name')."', remote host ".$rad_req->attr('NAS-IP-Address'), Priority => 'warning');
#		}
		sleep(1);
		$rad_resp->set_code( 'Access-Reject' );

		send_reply($SOCKET_RCV, $recv_udp_from_addr, $rad_req, $rad_resp, SERVER_SECRET);
		next;
	}

	if ( $userconf->{$rad_req->attr('User-Name')}->{'passwd'} ne $rad_req->password(SERVER_SECRET) ) {
		# PASSWORD MISMATCH
		logger("Auth-FAIL: Password mismatch for User-Name '".$rad_req->attr('User-Name')."', remote host ".$rad_req->attr('NAS-IP-Address') );
#		if ( RSYSLOG_ENABLE ) {
#			$rsyslog->send("Auth-FAIL: Password mismatch for User-Name '".$rad_req->attr('User-Name')."', remote host ".$rad_req->attr('NAS-IP-Address'), Priority => 'warning');
#		}
		sleep(1);
		$rad_resp->set_code( 'Access-Reject' );

		send_reply($SOCKET_RCV, $recv_udp_from_addr, $rad_req, $rad_resp, SERVER_SECRET);
		next;
	}


	# ACCESS GRANTED!
	$privlev = ( $userconf->{$rad_req->attr('User-Name')}->{'privlev'} eq 'admin' ) ? 'admin' : 'user';
	logger("Auth-OK: Access granted for User-Name '".$rad_req->attr('User-Name')."', remote host ".$rad_req->attr('NAS-IP-Address')." with privilege level '".$privlev."'" );
	if ( RSYSLOG_ENABLE ) {
		$rsyslog->send("Auth-OK: Access granted for User-Name '". $rad_req->attr('User-Name')."', remote host ".$rad_req->attr('NAS-IP-Address')." with privilege level '".$privlev."'", Priority => 'info');
	}
	$rad_resp->set_code( 'Access-Accept' );

	if ( $privlev eq 'admin' ) {
		# Admin level
		$rad_resp->set_vsattr( 'Dlink', 'Dlink-Privelege-Level' => 5 );
		$rad_resp->set_vsattr( 'Huawei', 'Huawei-Exec-Privilege' => 15 );
		$rad_resp->set_vsattr( 'Bdcom', 'Bdcom-Privelege-Level' => 15 );
		$rad_resp->set_vsattr( 'Cisco', 'Cisco-AVPair' => 'shell:priv-lvl=15' );
		$rad_resp->set_vsattr( 'APC', 'APC-Service-Type' => 1 );
	} else {
		# User level
		$rad_resp->set_vsattr( 'Dlink', 'Dlink-Privelege-Level' => 1 );
		$rad_resp->set_vsattr( 'Huawei', 'Huawei-Exec-Privilege' => 1 );
		$rad_resp->set_vsattr( 'Bdcom', 'Bdcom-Privelege-Level' => 1 );
		$rad_resp->set_vsattr( 'Cisco', 'Cisco-AVPair' => 'shell:priv-lvl=1' );
		$rad_resp->set_vsattr( 'APC', 'APC-Service-Type' => 3 );
	}
	send_reply($SOCKET_RCV, $recv_udp_from_addr, $rad_req, $rad_resp, SERVER_SECRET);
	next;

} # end while

logger("Terminating.\n");
norm_exit(0);


