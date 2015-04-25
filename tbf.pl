#!/usr/bin/perl
#
# Licensed under ABRHS
#

use strict;
use warnings;
use LWP::Curl;
use Term::ANSIColor;

my $ip;
my $md5;
my $curl = LWP::Curl->new();
my $term = "\ntbf > ";
my $help = qq{Threatbutt Framework help

  lolptions: 
    help  - Get this prompt
    ip    - Set threat IP to be attributed
    md5   - Set md5 hash for Threatbutt analysis
    proxy - Setup shoes proxy such as: 127.0.0.1:9050(WE ARE HUGE SUPPORTERS OF THE TOR PROJECT HERE)
    go    - Performs your desired task
    exit  - Quit
};

system("clear");
print '
                        ▄▄▄▓▓▓▓▓▓▌▄                                                 
                     ▄▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓µ                                              
                   ╓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▌                                             
                  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                            
                 ▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▄▀▓▓▓▓▌                                           
                ▓▓▓▓▓▓▓▓▓▓▓█▌▓▓▓▓▓Γ▀▓▓▓▓▓                        ,▄▌▌▄▄             
               ▄▓▓▓▓▓Γ▓▓▓▓▓╓▓▓▓▓▓█  ▓▌▓▓▓▓                      ╫▓.   Γ▀▀██▓▄▄      
             ╒▓▓▓▓▓ ▀▓╣▓▓▓▓▓▓▓▓▓█ ,▄▓▄▓▓▓▓                     ╓▓^ ╒▄ ,      ▀▓▄    
             ▓▓▓▓▓█ ╓▓▓▓▓▓▓▄▀█▓▄▓▓▓▓▓▓▓▓▓▓▓                    ▓▌  ▄µ,▀ ▀⌐╓▄  ▓▀    
             █▓▓▓▄▓█▓▓▓▓▓▓▓▓▓▓▓█▓▓▓██▀╠▓▓▓▓µ                  ▄▓  ▄▄ Γ`╜▀ ▓Γ ╬▓     
              ╟▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▀▀,▄▓▓▓▓▓██▓                 ╒▓  ╒▄ ƒ▀ █ ▓▌ ╓▓      
              ▐▓▓▓▓██▓▓▓▓▓█▀Γ,▄▄▓▓▓██▀Γ    ▓▓                ▓▀  ▄µ,▀ ▀⌐▐▓  ▓▀      
               ▓▄▄▓██▀▀▄▄▄▓▓▓▓██▀.          ▓▓           ▄▄▄▓▓  ╔▄ ▀ Å▀ ▓Γ ▓▓       
               ▓▓▓▓▓▓▓▓▓▓▀▀Γ        ▄╦ █▌    ▓▓     ▄▓█▀▀ΓΓ▀▓─ ╒▄ ╙▀ⁿ█ ▓▌ ╓▓        
               └▓▓▀▀Γ                ▓  ▓▄    ▓▓ ╓▓█Γ,    ,▓▓▄▄▄▄▄▓,█⌐▐▓  ▓Γ        
                █▓                    ▓ ▐▓     ▓▓▓   ▀█▓▓▓▀ΓΓ     Γ▀▀▓▓Γ ▓█         
                "▓µ                   █▄ █▓     ▓▌  ▀,▓▀              ▀▓▄▓          
                 ▓▓                    ▓  ▓µ     Γ   ▓Γ     ╕          █▓▀          
                  ▓▌                   ▐▓ ▐▓               █            ▓           
                   ▓▓                   █▌ ▓▓▄▄,                       ▓▓           
                    █▓µ                 ╓▓  ▄▄,▐▓▓        ,▄          ▐▓            
                     ╙▓▄                ▓Γ▓▄▀▓▀▀▀           ╓▒       ▄▓             
                       ▓▓╕              ▓▄▓█▓▓                 Φ   ,▓▓              
                        Γ▓▓              Γ                       ▄▓▓▀               
                          ╙▓▌,                             ▄▄▄▓▓█▀Γ                 
                            ▀█▓▄,                     ╓▄▓▌ ╙▓▄                      
                               Γ▀▓▓▌▄▄,       ,,▄▄▄▓▓█▀Γ└▓  ▓▓                      
                                   ΓΓ▀▀▀▓▓▀▓▓▀▀▀▀▀Γ ,,,  ▓▓ ╙▓                      
                                        █▌ ▓▌      ▀▓▓▀▀▀█▓M █▓                     
                                        ▓▌ ▓▌        ▀▓▓▄,    ▓                     
                                 ,▄▄▄,  ▓▌ ▓▌           Γ▀██▓▓▓Γ                    
                                 █▓▄Γ▀█▓▓▌]▓                                        
                                  ╙█▓▄  Γ ▐▓                                        
                                     Γ██▓▓▓▀                                        

                      --[ Threatbutt Framework v0.1.2 ]--';
while(1){
  print colored($term, 'underline');
  my $lol = <STDIN>;
  chomp($lol);
  if ($lol eq 'h'){
    print "h";
  } elsif ($lol eq 'help') {
    print $help;
  } elsif ($lol eq 'exit') {
    exit;
  } elsif ($lol =~ /^socks/) {
    $lol =~ s/socks //;
    $curl->proxy('http://' . $lol . '/');
  } elsif ($lol =~ /^ip/) {
    $lol =~ s/ip //;
    $ip = $lol;
    print "IP set: $ip";
  } elsif ($lol =~ /^md5/) {
    $lol =~ s/md5 //;
    $md5 = $lol;
    print "md5 set: $md5";
  } elsif ($lol eq 'go'){
    if ($ip) {
      my $attribute = { 
          'threat' => 'ip=' . $ip,
      };
      my $content = $curl->post('http://threatbutt.io/api', $attribute);

      print "\nGetting Threatbutt attribution on IP: $ip\nConnecting...\n";
      print "Establishing TLS 1.2 Handshake using TLS_RSA_WITH_AES_256_CBC_SHA_ETC_128...\n";
      sleep 2;
      print "Handshake failed, retrying... \n";
      sleep 2;
      print "Received data: $content\n";
      $ip = undef;
    } elsif ($md5) {
      my $dong = {
        'hash' => $md5,
      };
      my $content = $curl->post('http://threatbutt.io/api/md5/' . $md5, $dong);

      print "\nGetting Threatbutt analysis on md5: $md5\nConnecting...\n";
      print "Establishing TLS 1.2 Handshake using TLS_RSA_WITH_AES_256_CBC_SHA_ETC_128...\n";
      sleep 2;
      print "Handshake failed, retrying... \n";
      sleep 2;
      print "Received data: $content\n";
      $md5 = undef;
    } else {
      print "\nset your lolptions, butt.";
    }
  }
}
