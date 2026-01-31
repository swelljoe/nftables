#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);

sub script_dir
{
    my $path = $0;
    if ($path =~ m{^/}) {
        $path =~ s{/[^/]+$}{};
        return $path;
    }
    my $cwd = `pwd`;
    chomp($cwd);
    if ($path =~ m{/}) {
        $path =~ s{/[^/]+$}{};
        return $cwd.'/'.$path;
    }
    return $cwd;
}

my $bindir = &script_dir();

my $confdir = tempdir(CLEANUP => 1);
my $vardir = tempdir(CLEANUP => 1);
open(my $cfh, ">", "$confdir/config") or die "config: $!";
print $cfh "os_type=linux\nos_version=0\n";
close($cfh);
open(my $vfh, ">", "$confdir/var-path") or die "var-path: $!";
print $vfh "$vardir\n";
close($vfh);
$ENV{'WEBMIN_CONFIG'} = $confdir;
$ENV{'WEBMIN_VAR'} = $vardir;
$ENV{'FOREIGN_MODULE_NAME'} = 'nftables';
$ENV{'FOREIGN_ROOT_DIRECTORY'} = '/usr/libexec/webmin';

chdir("$bindir/..") or die "chdir: $!";

require "$bindir/../nftables-lib.pl";

sub check_fields
{
    my ($name, $got, $expect) = @_;
    foreach my $k (sort keys %$expect) {
        is($got->{$k}, $expect->{$k}, "$name $k");
    }
}

my @cases = (
    {
        name => 'tcp dport accept',
        line => 'tcp dport 22 accept',
        expect => { proto => 'tcp', dport => '22', action => 'accept' },
    },
    {
        name => 'iif oif drop',
        line => 'iif "eth0" oif "eth1" drop',
        expect => { iif => 'eth0', oif => 'eth1', action => 'drop' },
    },
    {
        name => 'comment with quotes',
        line => 'tcp dport 80 accept comment "a \\"quote\\""',
        expect => { proto => 'tcp', dport => '80', action => 'accept', comment => 'a "quote"' },
    },
    {
        name => 'ct state',
        line => 'ct state established,related accept',
        expect => { ct_state => 'established,related', action => 'accept' },
    },
    {
        name => 'icmp type',
        line => 'icmp type echo-request accept',
        expect => { icmp_type => 'echo-request', action => 'accept' },
    },
    {
        name => 'limit log counter',
        line => 'tcp dport 22 limit rate 10/second burst 20 packets log prefix "ssh" level info counter accept',
        expect => {
            proto => 'tcp',
            dport => '22',
            limit_rate => '10/second',
            limit_burst => '20',
            log_prefix => 'ssh',
            log_level => 'info',
            counter => 1,
            action => 'accept',
        },
    },
    {
        name => 'unknown tokens preserved',
        line => 'tcp dport 22 meta skgid 1000 accept',
        expect => { proto => 'tcp', dport => '22', action => 'accept' },
        preserve => 'meta skgid 1000',
    },
);

foreach my $c (@cases) {
    my $r = &parse_rule_text($c->{line});
    ok($r && ref($r) eq 'HASH', "$c->{name} parse hash");
    check_fields($c->{name}, $r, $c->{expect});

    my $out = &format_rule_text($r);
    ok($out =~ /\S/, "$c->{name} formatted non-empty");
    if ($c->{preserve}) {
        like($out, qr/\Q$c->{preserve}\E/, "$c->{name} preserves unknowns");
    }

    my $r2 = &parse_rule_text($out);
    check_fields($c->{name}.' roundtrip', $r2, $c->{expect});
}

my $ruleset = "$bindir/rulesets/basic.nft";
my @tables = &get_nftables_save($ruleset);
ok(@tables == 1, 'ruleset table count');
my $t = $tables[0];
is($t->{family}, 'inet', 'ruleset family');
is($t->{name}, 'filter', 'ruleset name');
my $chain = $t->{chains}->{input};
ok($chain, 'input chain present');
is($chain->{type}, 'filter', 'chain type');
is($chain->{hook}, 'input', 'chain hook');
is($chain->{priority}, '0', 'chain priority');
is($chain->{policy}, 'drop', 'chain policy');

my @rules = @{$t->{rules}};
check_fields('ruleset r1', $rules[0], { iif => 'lo', action => 'accept' });
check_fields('ruleset r2', $rules[1], { saddr => '192.168.1.0/24', proto => 'tcp', dport => '22', action => 'accept', comment => 'ssh' });
check_fields('ruleset r3', $rules[2], { ct_state => 'established,related', action => 'accept' });

done_testing();
