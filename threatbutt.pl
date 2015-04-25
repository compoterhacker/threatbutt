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

print "\nThreatbutt Client 0.1.0\n";
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

	print "$content\n\n";
} elsif ($md5) {
	my $dong = {
		'hash' => $md5,
	};
	my $content = $curl->post('http://threatbutt.io/api/md5/' . $md5, $dong);

	print "$content\n\n";
}
