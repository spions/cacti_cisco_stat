#!/usr/bin/perl

# ------------------------- #
# cisco_dhcp_stats.pl
# ------------------------- #
# 
# Description :
#   script to retrieve
#   DHCP infos on Cisco
#   routers who do not
#   support DHCP MIBs
# 
# 20101216 .Sam.
# http://www.l33.fr
# ------------------------- #

# 12.07.2012 + fradstat (c) Oleg Evdokimov



use strict;
no warnings "uninitialized";
#use warnings;
use Getopt::Long;
use Net::Telnet::Cisco;
use Time::Local;

# global vars
my ($appli,$host,$port,$username,$password,$enable,$pool,$result);

# process command line options :
# --host <hostname> --port <port> --username <username> --password <password> --enable <enable> --appli poolstats --pool <poolname>
# --host <hostname> --port <port> --username <username> --password <password> --enable <enable> --appli conflicts
# --host <hostname> --port <port> --username <username> --password <password> --enable <enable> --appli memstats

GetOptions( "host=s"    => \$host,
            "port=s"    => \$port,
            "username=s"=> \$username,
            "password=s"=> \$password,
            "enable=s"  => \$enable,
            "appli=s"   => \$appli,
            "pool:s"    => \$pool);

my $timeout = 200;

# cleaning function 
sub trim($)
{
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;

    return $string;
}

sub my_connect()
{
    # open a new session
    my $session = Net::Telnet::Cisco->new(
    Host => $host,
    Port => $port,
    Errmode => sub { die "Unable to connect to $host on port $port\n"; });

    # log in to the equipment
    $session->login(Name => $username,
                    Password => $password,
                    Timeout => $timeout); 

    return $session;
}

sub get_stats($)
{
    my $session = shift;

    # clean the term output
    $session->cmd('terminal length 0');

    # enable cisco mode
#    if ($session->enable($enable))
    {
        for ($appli)
        {
            if (/poolstats/)
            {
                my ($ipe,$ipl,$ipm) = fpool($session);
                $session->close;
                $result = "poolexcl:$ipe poolleased:$ipl poolmax:$ipm ";

                return $result;
            }
            elsif (/conflicts/)
            {
                my ($arpd,$pingd) = fconflicts($session);
                $session->close;
                $result = "arpdetect:$arpd pingdetect:$pingd ";

                return $result;
            }
            elsif (/memstats/)
            {
                my ($dmem) = fdmem($session);
                $session->close;
                $result = "$dmem";

                return $result;
            }
            elsif (/natstats/)
            {
		my @dm = ();
                my ($dmem) = fnat($session,$pool);
                $session->close;
                $result = "$dmem";
                return $result;
            }
            elsif (/nattranslation/)
            {
		my @dm = ();
                my ($allowed,$used,$missed) = fnattrans($session);
                $session->close;
                $result = "allowed:$allowed used:$used missed:$missed ";
                return $result;
            }

            elsif (/localstats/)
            {
                my ($ipe,$ipl,$ipm) = flocal($session);
                $session->close;
                $result = "poolfree:$ipl poolmax:$ipm pooluse:$ipe ";
                return $result;
            }
            elsif (/dhcpdstat/)
            {
		my ($dhcpdiscover,$dhcprequest,$dhcpinform,$dhcpoffer,$dhcpack,$dhcpnak,$dhcprelease,$dhcpdecline) = fdhcpd($session);
                $session->close;
                $result = "dhcpdiscover:$dhcpdiscover dhcprequest:$dhcprequest dhcpinform:$dhcpinform dhcpoffer:$dhcpoffer dhcpack:$dhcpack dhcpnak:$dhcpnak dhcprelease:$dhcprelease dhcpdecline:$dhcpdecline ";
                return $result;
            }
            elsif (/controlplane/)
            {
		my ($conformed1,$exceeded1,$conformed2,$exceeded2,$packets) = controlplane($session);
                $session->close;
                $result = "conformed1:$conformed1 exceeded1:$exceeded1 conformed2:$conformed2 exceeded2:$exceeded2 packets:$packets ";
                return $result;
            }

            elsif (/radstat/)
            {
		my ($accessrejects,$sessionsfailed) = fradstat($session);
                $session->close;
                $result = "accessrejects:$accessrejects sessionsfailed:$sessionsfailed ";
                return $result;
            }

            else
            {
                warn "ERROR: bad -a argument: " . $session->errmsg;
                $session->close;
                exit 0;
            }
        }
    }
#    else
#    {
#        warn "ERROR: can t enable: " . $session->errmsg;
#        $session->close;
#        exit 0;
#    }
}


sub fradstat($)
{
    my $session = shift;
    my ($c,$accessrejects,$sessionsfailed);
    $accessrejects=0;$sessionsfailed=0;

    $c="sh radius statistics | i Access Rejects";
    my @stats = $session->cmd($c);
    my ($e);
    foreach $e (@stats) {
        my @tl = split(':      ',$e);
        $tl[1]=~s/\s*//;
        substr($tl[1], -1) = '';
        $accessrejects = $tl[1];
    }


    $c="sh subscriber statistics |  i Number of sessions failed to come up";
    my @stats = $session->cmd($c);
    my ($e);
    foreach $e (@stats) {
        my @tl = split(': ',$e);
        $tl[1]=~s/\s*//;
        substr($tl[1], -1) = '';
        $sessionsfailed  = $tl[1];
    }
    if ($accessrejects=='') {$accessrejects=0;}
    if ($sessionsfailed=='') {$sessionsfailed=0;}
    return $accessrejects,$sessionsfailed;
}


sub fnattrans($)
{
    my $session = shift;
    my ($c,$allowed,$used,$missed);
    $allowed=0;$used=0;$missed=0;
    $c="sh ip nat sta | include max entry";
    my @stats = $session->cmd($c);
    my ($e);
    foreach $e (@stats) {
        my @tl = split(' ',$e);
	substr($tl[4], -1) = '';
	substr($tl[6], -1) = '';
        $allowed= $tl[4];
        $used = $tl[6];
        $missed = $tl[8];
#        $missed = timelocal(localtime())+950;
#	print localtime;
#	print timelocal(localtime());
        }
    return $allowed,$used,$missed;
}


sub fdhcpd($)
{
    my $session = shift;
    my ($c,$dhcpdiscover,$dhcprequest,$dhcpinform,$dhcpoffer,$dhcpack,$dhcpnak,$dhcprelease,$dhcpdecline);
    $dhcpdiscover=0;$dhcprequest=0;$dhcpinform=0;$dhcpoffer=0;
    $dhcpack=0; $dhcpnak=0; $dhcprelease=0; $dhcpdecline=0;
    $c="sh ip dhcp server statistics | i DHCP";
    my @stats = $session->cmd($c);
    my ($e);

    foreach $e (@stats) {
        my @tl = split(' ',$e);
	if (($tl[0] eq 'DHCPDISCOVER') && ($dhcpdiscover==0)) {$dhcpdiscover=$tl[1];}
	if (($tl[0] eq 'DHCPREQUEST') && ($dhcprequest==0)) {$dhcprequest=$tl[1];}
	if (($tl[0] eq 'DHCPINFORM') && ($dhcpinform==0)) {$dhcpinform=$tl[1];}
	if (($tl[0] eq 'DHCPOFFER')) {$dhcpoffer=$dhcpoffer+$tl[1];}

	if (($tl[0] eq 'DHCPDECLINE') && ($dhcpdecline==0)) {$dhcpdecline=$tl[1];}
	if (($tl[0] eq 'DHCPRELEASE') && ($dhcprelease==0)) {$dhcprelease=$tl[1];}
	if (($tl[0] eq 'DHCPACK') && ($dhcpack==0)) {$dhcpack=$tl[1];}
	if (($tl[0] eq 'DHCPNAK') && ($dhcpnak==0)) {$dhcpnak=$tl[1];}
        }
    return $dhcpdiscover,$dhcprequest,$dhcpinform,$dhcpoffer,$dhcpack,$dhcpnak,$dhcprelease,$dhcpdecline
}


sub flocal($)
{
    my $session = shift;
    my ($c,$ipe,$ipl,$ipm);
    $c="sh ip local pool | i  [0-9]";
    my @stats = $session->cmd($c);
    my ($e);
    $ipl=0; $ipe=0; $ipm=0;
    foreach $e (@stats) {
	my $e=substr($e,1);
	my $e='1'.$e;
        my @tl = split(' ',$e);
        # Free
        $ipl= $tl[3]+$ipl;
        # In use
        $ipe= $tl[4]+$ipe;
        }
    # get the max pool addr
    $ipm= $ipl+$ipe;

    return $ipe,$ipl,$ipm;
}

sub fpool($)
{
    my $session = shift;
    my ($c,$ipe,$ipl,$ipm);
    if ($pool)
    {
        $c="show ip dhcp pool $pool | i - [0-9]";
    }
    else
    {
        $c="show ip dhcp pool";
    }
    my @stats = $session->cmd($c);
    my ($e);
    $ipl=0; $ipe=0; $ipm=0;
    foreach $e (@stats) {
        my @tl = split(' ',$e);
        # get the max pool addr
        $ipm= $tl[8]+$ipm;
        # get current leased addr
        $ipl = $tl[4]+$ipl;
        # get nb of excluded addr
        $ipe = $tl[6]+$ipe;
        }
    return $ipe,$ipl,$ipm;
}

sub fconflicts($)
{
    my $session = shift;
    my ($arpd,$pingd);
    my @conflicts = $session->cmd('show ip dhcp conflict');
    my $line = trim(@conflicts);
    chomp($line);
    my @cf = split(' ',$line);
    my $i=0;
    {
        foreach (@cf)
        {
            if (/ARP/) {
                $i++;
                $arpd = $i;
            } else {
                $arpd = 0;
            }
            if (/Ping/) {
                $i++;
                $pingd = $i;
            } else {
                $pingd = 0;
            }
        }
    }

    return ($arpd,$pingd);
}

sub fdmem($)
{
    my $session = shift;
    my ($dmem);
    my @serv = $session->cmd('show ip dhcp server statistics');
    my $line = trim($serv[0]);
    chomp($line);
    my @dm = split(' ',$line);
    $dmem = $dm[2];

    return ($dmem);
}


sub controlplane($)
{
    my $session = shift;

    my ($conformed1,$exceeded1,$conformed2,$exceeded2,$packets);

    my @serv = $session->cmd('sh policy-map control-plane input class ARP | i (conformed.*actions|exceeded.*actions)');
    my ($e);
    foreach $e (@serv) {
	my @tl = split(' ',$e);
	if ($tl[0] eq 'conformed') {$conformed1=$tl[1];}
	if ($tl[0] eq 'exceeded') {$exceeded1=$tl[1];}
    }

    my @serv = $session->cmd('sh policy-map control-plane input class coppacl-dhcp-requests | i (conformed.*actions|exceeded.*actions)');
    my ($e);
    foreach $e (@serv) {
	my @tl = split(' ',$e);
	if ($tl[0] eq 'conformed') {$conformed2=$tl[1];}
	if ($tl[0] eq 'exceeded') {$exceeded2=$tl[1];}
    }

    my @serv = $session->cmd('sh policy-map control-plane input class class-default | i (packets)');
    my ($e);
    foreach $e (@serv) {
	my @tl = split(' ',$e);
	if ($tl[1] eq 'packets,') {$packets=$tl[0];}
    }
    return ($conformed1,$exceeded1,$conformed2,$exceeded2,$packets);
}

sub fnat($)
{
    my $session = shift;
    my ($dmem);
    my ($q);
#    $session->autopage(0);
#    $session->normalize_cmd(0);

    my $i;
    $i=0;
    
    my @serv = $session->cmd('sh ip nat sta | section type generic|pool');

#    chomp($line);

    foreach $q (@serv) {
    if  ($q  =~  $pool) { $i=1; }
        if (($q  =~  'type') and ($i==1)) {
            my @dm = split(' ',$q);
            substr($dm[4], -1) = '';
            $dmem = "allocated:".$dm[6]." pooltotal:".$dm[4]." ";
    return ($dmem);
        }

    }
#    return ($dmem);
}

my $s = my_connect();
get_stats($s);
print $result;
