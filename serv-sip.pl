#!/usr/bin/perl

my $PORT = 5060;
my $PROTO = shift || "tcp";

use IO::Socket;
use strict;

my $sock = IO::Socket::INET->new(
	LocalPort => $PORT,
	ReuseAddr => 1,
	Blocking => $PROTO eq "udp",
	Proto => $PROTO,
	($PROTO eq "tcp" ? (Listen => 1) : ())
) || die $!;
my $cli;
print "Listening on port $PORT ($PROTO)\n";
my $DATA = join "", <DATA>;
my $msg;
my @get;
my $get;
$SIG{INT} = sub { close($sock); close($cli); die; };

if ($PROTO eq "udp")
{
	while ($cli = $sock->recv($msg, 1024*4, 0))
	{
		print "- connected\n";
#my ($port, $ip) = unpack_sockaddr_in($client);
#my $host = gethostbyaddr($ip, AF_INET);
#print "Client $host:$port sent '$message' at ", scalar(localtime), "\n";
#$server->send("Message '$message' received", 0, $client);
		$get = @get = map { "$_\n" } split(/\n/, $msg);
		start();
	}
#$cli = $sock;
}
else
{
	while (1)
	{
		if ($cli = $sock->accept)
		{
			print "- connected\n";
			eval {
				local $SIG{ALRM} = sub { die };
				alarm(5);	
				start();
				alarm(0);
			};
			eval { close($cli); };
		}
		select(undef, undef, undef, 0.1);
	}
print "ah\n";
}

sub start
{
	my %vars;
	my $reg;
	my $msg;
	#while ($msg !~ /\r?\n\r?\n/) {
	while (!$reg)
	{
	# TODO add timeout
	# TODO support multiple users
		while (1)
		{
			my $tmp = get();
			$reg++ if $tmp =~ /^\0*REGISTER|POST \/(samy_pktsiz|packet_size)/;
			$tmp =~ s/\r//g;
			$vars{uc($1)} = $2 if $tmp =~ /^(\S+):\s*(.*)/;
			$msg .= $tmp;
			last if $tmp =~ /^\r?\n$/;
		}
		#select(undef, undef, undef, 0.100);
	}

	if ($msg =~ /^POST \/(samy_pktsiz|packet_size)/)
	{
		if ($vars{"CONTENT-LENGTH"})
		{
			my $total;
			while ($total != $vars{"CONTENT-LENGTH"})
			{
				my $tmp;
				my $read = $cli->read($tmp, $vars{"CONTENT-LENGTH"}-$total);
				$total += length($tmp);
				$tmp =~ s/ {5,}/.../;
				print "read r=$read cl=$vars{'CONTENT-LENGTH'} len=" . length($tmp)."  ($tmp)\n";
			}
print "p4\n";
			my $ret = << "EOF";
HTTP/1.1 200 OK
Server: samy natpin v2
X-Easter-Egg: You found Easter Egg #15!
Cache-Control: max-age=0, no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Connection: close
Content-Length: 0
Content-Type: text/html
EOF
			$ret .= "\n";
			$ret =~ s/\r?\n/\r\n/g;
			out($ret) unless $vars{"NO-HTTP"};
			#print $cli $ret;
		}
		if ($vars{"CLOSE"} =~ /no/i) { start(); }
		else { close($cli); }
		return;
	}

	my $resp = $DATA;
	$resp =~ s/\n/\r\n/g;
	$resp =~ s/\{(.*?)\}/$vars{$1}/eg;
	$resp .= "\r\n";
		
	my $len = length($resp);
	my $hdr = <<"EOF";
HTTP/1.1 200 OK
Date: Sun, 14 Apr 2019 16:34:00 GMT
Server: samy natpin v2
X-Easter-Egg: You found Easter Egg #15!
Content-Length: $len
Keep-Alive: timeout=5, max=98
Connection: close
Content-Type: text/html
EOF
	$hdr .= "\n";
	$hdr =~ s/\r?\n/\r\n/g;

	out($hdr) unless $vars{"NO-HTTP"};
	# force 100ms to split packets in two
	select(undef, undef, undef, 0.1);
	out($resp);

	if ($vars{"CLOSE"} =~ /no/i) { start(); }
	else { close($cli); }
	#close($cli);
}

sub get
{
	my $in = $get ? shift(@get) : <$cli>;
	print "< $in" if (length($in));
	return $in;
}

sub out
{
	my $msg = shift;
	#$msg .= "\r\n" if ($msg !~ /\r\n/);
	print "> $msg";
	#print $cli $msg;
	$PROTO eq "udp" ? $sock->send($msg, 0, $cli) : $cli->send($msg);
}

__DATA__
SIP/2.0 200 OK
Via: {VIA};received=192.0.2.201
From: {FROM}
To: {TO};tag=37GkEhwl6
Call-ID: {CALL-ID}
CSeq: {CSEQ}
Contact: {CONTACT};expires=3600
Content-Length: 0
