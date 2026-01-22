#!/usr/bin/perl
# edit_rule.cgi
# Display a form for creating or editing a rule

require './nftables-lib.pl';
use strict;
use warnings;
our (%in, %text, %config);
&ReadParse();
my @tables = &get_nftables_save();
my $table = $tables[$in{'table'}];
my $rule;
my $chain_def;
my $chain_hook;

if ($in{'new'}) {
    &ui_print_header(undef, $text{'edit_title_new'}, "", "intro", 1, 1);
    $rule = { 'chain' => $in{'chain'} };
} else {
    &ui_print_header(undef, $text{'edit_title_edit'}, "", "intro", 1, 1);
    $rule = $table->{'rules'}->[$in{'idx'}];
}
if ($table && $rule->{'chain'}) {
    $chain_def = $table->{'chains'}->{$rule->{'chain'}};
    $chain_hook = $chain_def ? $chain_def->{'hook'} : undef;
}

print &ui_form_start("save_rule.cgi");
print &ui_hidden("table", $in{'table'});
print &ui_hidden("idx", $in{'idx'});
print &ui_hidden("chain", $rule->{'chain'});
print &ui_hidden("new", $in{'new'});

print &ui_table_start($text{'edit_header'}, "width=100%", 2);

# Rule comment
print &ui_table_row($text{'edit_comment'},
    &ui_textbox("comment", $rule->{'comment'}, 50));

# Action
print &ui_table_row($text{'edit_action'},
    &ui_select("action", $rule->{'action'},
    [
        [ "accept", $text{'index_accept'} ],
        [ "drop", $text{'index_drop'} ],
        [ "reject", $text{'index_reject'} ],
    ]));

# Protocol
print &ui_table_row($text{'edit_proto'},
    &ui_select("proto", $rule->{'proto'},
    [
        [ "tcp", "TCP" ],
        [ "udp", "UDP" ],
        [ "icmp", "ICMP" ],
    ]));

# Destination port
print &ui_table_row($text{'edit_dport'},
    &ui_textbox("dport", $rule->{'dport'}, 10));

if ($chain_hook && $chain_hook eq 'input') {
    # Incoming interface
    print &ui_table_row($text{'edit_iif'},
        &interface_choice("iif", $rule->{'iif'}, $text{'edit_if_any'}));
}
elsif ($chain_hook && $chain_hook eq 'output') {
    # Outgoing interface
    print &ui_table_row($text{'edit_oif'},
        &interface_choice("oif", $rule->{'oif'}, $text{'edit_if_any'}));
}
else {
    # Forward or unknown chain - allow both
    print &ui_table_row($text{'edit_iif'},
        &interface_choice("iif", $rule->{'iif'}, $text{'edit_if_any'}));
    print &ui_table_row($text{'edit_oif'},
        &interface_choice("oif", $rule->{'oif'}, $text{'edit_if_any'}));
}

print &ui_table_end();
my @buttons;
if ($in{'new'}) {
    push(@buttons, [ undef, $text{'create'} ]);
} else {
    push(@buttons, [ undef, $text{'save'} ]);
    push(@buttons, [ 'delete', $text{'delete'} ]);
}
print &ui_form_end(\@buttons);

&ui_print_footer("index.cgi?table=$in{'table'}", $text{'index_return'});
