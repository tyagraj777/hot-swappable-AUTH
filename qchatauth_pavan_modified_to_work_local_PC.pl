use strict;
use Digest::MD5;
use Digest::SHA;
use Bytes::Random;
use Switch;
# use ...
# This is very important ! Without this script will not get the filled hashesh from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG);
use Data::Dumper;

# This is hash wich hold original request from radius
#my %RAD_REQUEST;
# In this hash you add values that will be returned to NAS.
#my %RAD_REPLY;
#This is for check items
#my %RAD_CHECK;

#
# This the remapping of return values
#
	use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
	use constant	RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
	use constant	RLM_MODULE_OK=>        2;#  /* the module is OK, continue */
	use constant	RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
	use constant	RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
	use constant	RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
	use constant	RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
	use constant	RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
	use constant	RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
	use constant	RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */

#my $IMSI='310006191234567';
my $IMSI='440793123456803';

&makeBAKNII;
&makeBAK;

sub makeBAKNII {
                            print "makeBAKNII started\n";
							
        #&radiusd::radlog(1, "BAKSeed to BAK Conversion");
        #&radiusd::radlog(1, "BAKSeed: \"".$RAD_REQUEST{'User-Password'}."\"");

        #convert to binary
		#my $hexPassword = unpack "H*", $RAD_REQUEST{'User-Password'};
#		my $hexPassword = unpack "H*",'310006191234567';
		my $hexPassword = unpack "H*",$IMSI;
	#&radiusd::radlog(1,"Hex Password\"".$hexPassword."\"");
           print "makeBAKNII - IMSI - in hexadecimal - hexPassword: $hexPassword\n";
		   
        #BAK = SHA256(binaryBAKSeed:create_bak); # This is for pavan understanding
        my $carrierString;
	#if(exists $static_global_qchat_conf{'carrier_string'}) {
	 #       $carrierString = $static_global_qchat_conf{'carrier_string'}; 
	#}
	#else {
		#default value
		$carrierString = 'create_bak';
	#}
		
	my $hexCarrierString =unpack "H*",$carrierString;
						print ("carrierString in hexadecimal : $hexCarrierString\n");  # This is for pavan understanding
	#&radiusd::radlog(1,"Hex Carrier String\"".$hexCarrierString."\"");  # pavan commented

        #my $ctx = Digest::SHA->new('SHA-256');
		my $ctx = Digest::SHA->new('HMAC-SHA-1');
		
		
		
	    $ctx->add($hexPassword.":".$hexCarrierString);
        my $hexdigest = $ctx->hexdigest();
        $hexdigest = substr($hexdigest, 32);
        #&radiusd::radlog(1, "BAK: \"".$hexdigest."\"");   # Pavan commented 
		print "makeBAKNII-BAK-hexdigest:$hexdigest\n";
		print "makeBAKNII completed\n";
}

sub makeBAK {
						print "\n \n makeBAK started\n";
        #&radiusd::radlog(1, "BAKSeed to BAK Conversion");
        #&radiusd::radlog(1, "BAKSeed: \"".$RAD_REQUEST{'User-Password'}."\"");

        #convert to binary
        #my $binPassword = pack "H*", $RAD_REQUEST{'User-Password'};
        #my $binPassword = $RAD_REQUEST{'User-Password'};
		#my $binPassword = '310006191234567';
			my $binPassword = $IMSI;
        $binPassword =~ s/(.)/sprintf("%x",ord($1))/eg;
	                         print "makeBAK - IMSI- in hexadecimal - binPassword: $binPassword\n";

        #BAK = SHA256(binaryBAKSeed:create_bak);
        my $carrierString;
	#if(exists $static_global_qchat_conf{'carrier_string'}) {
	#        $carrierString = $static_global_qchat_conf{'carrier_string'}; 
	#}
	#else {
		#default value
		$carrierString = 'create_bak';
	#}
        $carrierString =~ s/(.)/sprintf("%x",ord($1))/eg;
        #$carrierString = uc($carrierString);
						print ("carrierString in hex: $carrierString\n");  # This is for pavan understanding
        my $ctx = Digest::SHA->new('SHA-256');
        $ctx->add($binPassword);
        $ctx->add(":");
        $ctx->add($carrierString);
        my $hexdigest = $ctx->hexdigest();


        #&radiusd::radlog(1, "BAK: \"".$hexdigest."\"");
        $hexdigest = substr($hexdigest, 32);
		
				print "makeBAK-BAK-hexdigest:$hexdigest\n";  # This is for pavan understanding 
		
        my $bindigest = pack "H*", $hexdigest;
        #&radiusd::radlog(1, "Lower-128-bits: \"".$hexdigest."\"");
        $RAD_REQUEST{'User-Password'} = $bindigest;
}