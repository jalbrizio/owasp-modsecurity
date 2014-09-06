#!/usr/bin/perl
# Credit to Ryan Barnett at Spiderlabs.com for original idea
 
use strict;
use warnings;
use Getopt::Std;
use vars qw/ %opt /;
my $options = 'haf:s:';
my $defaultlog = '/usr/local/apache/logs/modsec_audit.log';
getopts( "$options", \%opt ) or &help();
&help() if ($opt{h} or !%opt);
my $sstr;
my $count=0;
my %rules;
 
if ($opt{f}) {
    open(LOGFILE,'<',$opt{f}) || die "cant find $opt{f} file $!\n";
} else {
    open(LOGFILE,'<',$defaultlog) || die "cant find $defaultlog file $!\n";
}
 
if ($opt{s}) {
    $sstr = $opt{s};
} else {
    die 'Nothing to search for';
}
 
# Slurp up to the end of the next Z Section
$/ = "-Z--\n"; 
 
while(my $chunk = <LOGFILE>) {
    chomp $chunk;
    if (($chunk =~ m/ Intercepted/ || $opt{a}) && $chunk =~ m/$sstr/) {
        $count++;
        # If you use a ruleset other than Atomic's then you can change the regex below to grab the rule's ID number and descriptive text
        if ($chunk =~ m/\[id "([\d]+)"\].+WAF Rules([^"\]]{1,100})/) {    
            $rules{$1}{count}++;
            $rules{$1}{msg} = $rules{$1}{msg} ? $rules{$1}{msg} : $2;
        }
        print "####################\nEntry found for search String ($sstr)\n####################\n";
        print $chunk,"-Z--\n\n";
    }
}
close (LOGFILE);
 
print "\n\nTotal Matches for $sstr : $count\n";
foreach my $rule (keys %rules) {
    print "$rule - $rules{$rule}{count} - $rules{$rule}{msg}\n";
}
 
exit;
 
sub help() {
    print << "EOF";
 
$0 [-h] [-a] [-f file] [-s search]
 
    default   : same as -h
    -h        : this help message
    -a        : show all activity (defaults to Interceptions only)
    -f file   : file to search (defaults to /usr/local/apache/logs/modsec_audit.log)
    -s search : string to match on - enclosed in quotes if it contains spaces
EOF
    exit;
}
