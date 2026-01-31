#!/usr/bin/perl
# save_rule.cgi
# Save a new or existing rule

require './nftables-lib.pl';
use strict;
use warnings;
our (%in, %text, %config);
&ReadParse();
&error_setup($text{'save_err'});
my @tables = &get_nftables_save();
my $table = $tables[$in{'table'}];

if ($in{'delete'}) {
    # Delete the rule
    my $rule = $table->{'rules'}->[$in{'idx'}];
    splice(@{$table->{'rules'}}, $in{'idx'}, 1);
    &webmin_log("delete", "rule", $rule ? $rule->{'text'} : undef);
} else {
    my $rule = {};
    if ($in{'new'}) {
        $rule->{'chain'} = $in{'chain'};
        $rule->{'index'} = scalar(@{$table->{'rules'}});
    } else {
        $rule = $table->{'rules'}->[$in{'idx'}];
    }

    $rule->{'comment'} = $in{'comment'};
    my $action = $in{'action'} || 'accept';
    $rule->{'action'} = undef;
    $rule->{'jump'} = undef;
    $rule->{'goto'} = undef;
    if ($action eq 'jump') {
        $rule->{'jump'} = $in{'jump'};
    }
    elsif ($action eq 'goto') {
        $rule->{'goto'} = $in{'goto'};
    }
    else {
        $rule->{'action'} = $action;
    }

    $rule->{'saddr'} = (defined($in{'saddr'}) && $in{'saddr'} ne '') ? $in{'saddr'} : undef;
    $rule->{'daddr'} = (defined($in{'daddr'}) && $in{'daddr'} ne '') ? $in{'daddr'} : undef;
    $rule->{'saddr_family'} = $rule->{'saddr'} ? &guess_addr_family($rule->{'saddr'}) : undef;
    $rule->{'daddr_family'} = $rule->{'daddr'} ? &guess_addr_family($rule->{'daddr'}) : undef;

    my $proto = $in{'proto'};
    $proto = undef if (defined($proto) && $proto eq '');
    $rule->{'sport'} = (defined($in{'sport'}) && $in{'sport'} ne '') ? $in{'sport'} : undef;
    $rule->{'dport'} = (defined($in{'dport'}) && $in{'dport'} ne '') ? $in{'dport'} : undef;
    if (!$proto && ($rule->{'sport'} || $rule->{'dport'})) {
        $proto = 'tcp';
    }
    $rule->{'l4proto'} = undef;
    $rule->{'l4proto_family'} = undef;
    $rule->{'proto'} = undef;
    $rule->{'sport_proto'} = undef;
    if ($proto && ($proto eq 'tcp' || $proto eq 'udp')) {
        $rule->{'proto'} = $proto if ($rule->{'sport'} || $rule->{'dport'});
        $rule->{'sport_proto'} = $proto if ($rule->{'sport'});
    }
    elsif ($proto && $proto !~ /^(tcp|udp)$/) {
        $rule->{'sport'} = undef;
        $rule->{'dport'} = undef;
    }
    if ($proto) {
        if (($proto eq 'tcp' || $proto eq 'udp') && ($rule->{'sport'} || $rule->{'dport'})) {
            # L4 proto implied by port match
        }
        else {
            $rule->{'l4proto'} = $proto;
            $rule->{'l4proto_family'} = 'meta';
        }
    }

    my $icmp_type = $in{'icmp_type'};
    $rule->{'icmp_type'} = undef;
    $rule->{'icmpv6_type'} = undef;
    if ($proto && $proto eq 'icmp') {
        $rule->{'icmp_type'} = $icmp_type if (defined($icmp_type) && $icmp_type ne '');
    }
    elsif ($proto && $proto eq 'icmpv6') {
        $rule->{'icmpv6_type'} = $icmp_type if (defined($icmp_type) && $icmp_type ne '');
    }
    elsif (!$proto && defined($icmp_type) && $icmp_type ne '') {
        $rule->{'icmp_type'} = $icmp_type;
        $rule->{'l4proto'} = 'icmp';
        $rule->{'l4proto_family'} = 'meta';
    }

    $rule->{'ct_state'} = (defined($in{'ct_state'}) && $in{'ct_state'} ne '') ? $in{'ct_state'} : undef;
    $rule->{'tcp_flags'} = (defined($in{'tcp_flags'}) && $in{'tcp_flags'} ne '') ? $in{'tcp_flags'} : undef;
    $rule->{'tcp_flags_mask'} = (defined($in{'tcp_flags_mask'}) && $in{'tcp_flags_mask'} ne '') ? $in{'tcp_flags_mask'} : undef;
    $rule->{'limit_rate'} = (defined($in{'limit_rate'}) && $in{'limit_rate'} ne '') ? $in{'limit_rate'} : undef;
    $rule->{'limit_burst'} = (defined($in{'limit_burst'}) && $in{'limit_burst'} ne '') ? $in{'limit_burst'} : undef;

    my $log_enabled = $in{'log'} || $in{'log_prefix'} || $in{'log_level'};
    $rule->{'log'} = $log_enabled ? 1 : undef;
    $rule->{'log_prefix'} = $log_enabled && defined($in{'log_prefix'}) && $in{'log_prefix'} ne '' ? $in{'log_prefix'} : undef;
    $rule->{'log_level'} = $log_enabled && defined($in{'log_level'}) && $in{'log_level'} ne '' ? $in{'log_level'} : undef;
    $rule->{'counter'} = $in{'counter'} ? 1 : undef;

    my $iif = $in{'iif'};
    my $oif = $in{'oif'};
    $iif = $in{'iif_other'} if (defined($iif) && $iif eq 'other');
    $oif = $in{'oif_other'} if (defined($oif) && $oif eq 'other');
    $rule->{'iif'} = (defined($iif) && $iif ne '') ? $iif : undef;
    $rule->{'oif'} = (defined($oif) && $oif ne '') ? $oif : undef;

    $rule->{'text'} = &format_rule_text($rule);

    if ($in{'new'}) {
        push(@{$table->{'rules'}}, $rule);
    }
    &webmin_log("save", $in{'new'} ? "create" : "modify", $rule->{'text'});
}
my $err = &save_configuration(@tables);
&error(&text('save_failed', $err)) if ($err);
&redirect("index.cgi?table=$in{'table'}");
