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
my $action_sel;
my $proto_sel;
my $icmp_type;
my $log_enabled;

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
if ($rule) {
    if ($rule->{'jump'}) {
        $action_sel = 'jump';
    }
    elsif ($rule->{'goto'}) {
        $action_sel = 'goto';
    }
    else {
        $action_sel = $rule->{'action'};
    }
    $action_sel ||= 'accept';
    $proto_sel = $rule->{'proto'} || $rule->{'l4proto'};
    if (!$proto_sel) {
        $proto_sel = 'icmp' if ($rule->{'icmp_type'});
        $proto_sel = 'icmpv6' if ($rule->{'icmpv6_type'});
    }
    $proto_sel ||= 'tcp' if ($in{'new'});
    $icmp_type = $rule->{'icmp_type'} || $rule->{'icmpv6_type'};
    $log_enabled = $rule->{'log'} || $rule->{'log_prefix'} || $rule->{'log_level'};
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
    &ui_select("action", $action_sel,
    [
        [ "accept", $text{'index_accept'} ],
        [ "drop", $text{'index_drop'} ],
        [ "reject", $text{'index_reject'} ],
        [ "return", $text{'edit_return'} ],
        [ "jump", $text{'edit_jump_action'} ],
        [ "goto", $text{'edit_goto_action'} ],
    ]));

# Jump/Goto target chain
print &ui_table_row($text{'edit_jump'},
    &ui_textbox("jump", $rule->{'jump'}, 20));
print &ui_table_row($text{'edit_goto'},
    &ui_textbox("goto", $rule->{'goto'}, 20));

# Interfaces
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

# Addresses
print &ui_table_row($text{'edit_saddr'},
    &ui_textbox("saddr", $rule->{'saddr'}, 30));
print &ui_table_row($text{'edit_daddr'},
    &ui_textbox("daddr", $rule->{'daddr'}, 30));

# Protocol
print &ui_table_row($text{'edit_proto'},
    &ui_select("proto", $proto_sel,
    [
        [ "", $text{'edit_proto_any'} ],
        [ "tcp", "TCP" ],
        [ "udp", "UDP" ],
        [ "icmp", "ICMP" ],
        [ "icmpv6", "ICMPv6" ],
    ]));

# Ports
print &ui_table_row($text{'edit_sport'},
    &ui_textbox("sport", $rule->{'sport'}, 10));
print &ui_table_row($text{'edit_dport'},
    &ui_textbox("dport", $rule->{'dport'}, 10));

# ICMP type
print &ui_table_row($text{'edit_icmp_type'},
    &ui_textbox("icmp_type", $icmp_type, 20));

# Conntrack state
print &ui_table_row($text{'edit_ct_state'},
    &ui_textbox("ct_state", $rule->{'ct_state'}, 30));

# TCP flags
print &ui_table_row($text{'edit_tcp_flags'},
    &ui_textbox("tcp_flags", $rule->{'tcp_flags'}, 20));
print &ui_table_row($text{'edit_tcp_flags_mask'},
    &ui_textbox("tcp_flags_mask", $rule->{'tcp_flags_mask'}, 20));

# Limit
print &ui_table_row($text{'edit_limit_rate'},
    &ui_textbox("limit_rate", $rule->{'limit_rate'}, 20));
print &ui_table_row($text{'edit_limit_burst'},
    &ui_textbox("limit_burst", $rule->{'limit_burst'}, 10));

# Log
my $log_row = &ui_checkbox("log", 1, $text{'edit_log_enable'}, $log_enabled);
$log_row .= "<br>".&text('edit_log_prefix', &ui_textbox("log_prefix", $rule->{'log_prefix'}, 20));
$log_row .= " ".&text('edit_log_level', &ui_textbox("log_level", $rule->{'log_level'}, 10));
print &ui_table_row($text{'edit_log'}, $log_row);

# Counter
print &ui_table_row($text{'edit_counter'},
    &ui_checkbox("counter", 1, $text{'edit_counter_enable'}, $rule->{'counter'}));

# Raw rule (read-only)
print &ui_table_row($text{'edit_raw_rule'},
    &ui_textarea("raw_rule", $rule->{'text'}, 4, 60, undef, undef,
                 "readonly='true'"));

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
