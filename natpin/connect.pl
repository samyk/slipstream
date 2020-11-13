#!/usr/bin/perl

use IO::Socket;
use strict;
$|++;

die "usage: $0 <ip> <port>\n" unless @ARGV == 2;
my $sock = IO::Socket::INET->new(PeerAddr => $ARGV[0], PeerPort => $ARGV[1], Timeout => 4);
my $data = "";
if (!$sock)
{
	p("log(\"couldn't reach $ARGV[0]:$ARGV[1]: $!\");\n");
}
else
{
	p("log('<b>connected to $ARGV[0]:$ARGV[1]</b>');\n");
	print $sock "hello from samy.pl!\r\n";
	eval {
		$SIG{ALRM} = sub { die };
		alarm(4);
		while (<$sock>) 
		{
			p("log('$ARGV[0]:$ARGV[1]: " . join("", map { "\\x" . unpack("H2", $_) } split(//, $_)) . "');\n");
		}
		#$data .= $_ while <$sock>;
		alarm(0);
	};
	#if ($@) { print "$@ - $!\n" }
	#print "log('$ARGV[0]:$ARGV[1]: " . join("", map { "\\x" . unpack("H2", $_) } split(//, $data)) . "');\n";	
}
print "connectDone()\n";

sub p
{
	print $_[0];

	open(F, ">>/tmp/.con.log");
	print F $_[0];
	close F;
}
