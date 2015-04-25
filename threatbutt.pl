#!/usr/bin/perl
#
# Licensed under ABRMS
#

use strict;
use warnings;
use LWP::Curl;
use Getopt::Long qw(GetOptions);

my $ip;
my $md5;
my $curl = LWP::Curl->new();

print "\nThreatbutt Client 0.1.1\n";
if (!@ARGV) { die "\nUsage: \nperl $0 --ip IPADDR\nperl $0 --md5 HASH\n\n"; }

GetOptions(
	'ip=s' => \$ip,
	'md5=s' => \$md5,
) or die "\nUsage: \nperl $0 --ip IPADDR\nperl $0 --md5 HASH\n\n";

if ($ip) {
	my $attribute = { 
		'threat' => 'ip=' . $ip,
	};
	my $content = $curl->post('http://threatbutt.io/api', $attribute);

	print "Connecting...\n";
	print "Establishing TLS 1.2 Handshake using TLS_RSA_WITH_AES_256_CBC_SHA_ETC128...\n";
	sleep 2;
	print "Handshake failed, retrying... \n";
	sleep 2;
	print "Received data: $content\n\n";
} elsif ($md5) {
	my $dong = {
		'hash' => $md5,
	};
	my $content = $curl->post('http://threatbutt.io/api/md5/' . $md5, $dong);

	print "Connecting...\n";
	print "Establishing TLS 1.2 Handshake using TLS_RSA_WITH_AES_256_CBC_SHA_ETC128...\n";
	sleep 2;
	print "Handshake failed, retrying... \n";
	sleep 2;
	print "Received data: $content\n\n";
}
