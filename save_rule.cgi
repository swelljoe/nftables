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
    $rule->{'action'} = $in{'action'};
    $rule->{'proto'} = $in{'proto'};
    $rule->{'dport'} = $in{'dport'};
    my $iif = $in{'iif'};
    my $oif = $in{'oif'};
    $iif = $in{'iif_other'} if (defined($iif) && $iif eq 'other');
    $oif = $in{'oif_other'} if (defined($oif) && $oif eq 'other');
    $rule->{'iif'} = (defined($iif) && $iif ne '') ? $iif : undef;
    $rule->{'oif'} = (defined($oif) && $oif ne '') ? $oif : undef;

    my $rule_text = "";
    if ($rule->{'proto'} && $rule->{'dport'}) {
        $rule_text .= "$rule->{'proto'} dport $rule->{'dport'} ";
    }
    if ($rule->{'iif'}) {
        $rule_text .= "iif \"$rule->{'iif'}\" ";
    }
    if ($rule->{'oif'}) {
        $rule_text .= "oif \"$rule->{'oif'}\" ";
    }
    $rule_text .= $rule->{'action'};
    if ($rule->{'comment'}) {
        my $comment = $rule->{'comment'};
        $comment =~ s/\\/\\\\/g;
        $comment =~ s/"/\\"/g;
        $rule_text .= " comment \"$comment\"";
    }
    $rule->{'text'} = $rule_text;

    if ($in{'new'}) {
        push(@{$table->{'rules'}}, $rule);
    }
    &webmin_log("save", $in{'new'} ? "create" : "modify", $rule->{'text'});
}
my $err = &save_configuration(@tables);
&error(&text('save_failed', $err)) if ($err);
&redirect("index.cgi?table=$in{'table'}");
