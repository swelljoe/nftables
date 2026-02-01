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
my $raw_extra = "";

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
    if ($rule->{'exprs'} && ref($rule->{'exprs'}) eq 'ARRAY') {
        my @raw = map { $_->{'text'} }
                  grep { $_->{'type'} && $_->{'type'} eq 'raw' }
                  @{$rule->{'exprs'}};
        $raw_extra = join(" ", @raw);
    }
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
print &ui_hidden("raw_extra", $raw_extra);

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

# Raw rule (read-only unless edit direct is checked)
my $raw_controls = &ui_checkbox("edit_direct", 1, $text{'edit_raw_rule_direct'}, 0);
my $raw_area = &ui_textarea("raw_rule", $rule->{'text'}, 4, 60, undef, undef,
                            "readonly='true'");
print &ui_table_row($text{'edit_raw_rule'}, $raw_controls."<br>".$raw_area);

print &ui_table_end();
my @buttons;
if ($in{'new'}) {
    push(@buttons, [ undef, $text{'create'} ]);
} else {
    push(@buttons, [ undef, $text{'save'} ]);
    push(@buttons, [ 'delete', $text{'delete'} ]);
}
print &ui_form_end(\@buttons);

print <<'EOF';
<script>
(function() {
  function byName(name) {
    var els = document.getElementsByName(name);
    return els && els.length ? els[0] : null;
  }
  function val(name) {
    var el = byName(name);
    if (!el) return "";
    if (el.type === "checkbox") {
      return el.checked ? (el.value || "1") : "";
    }
    return el.value || "";
  }
  function ifaceVal(name) {
    var v = val(name);
    if (v === "other") {
      return val(name + "_other");
    }
    return v;
  }
  function escapeNft(s) {
    return s.replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
  }
  function isNumeric(s) {
    return /^[0-9]+$/.test(s);
  }
  function guessFamily(addr) {
    return addr.indexOf(":") >= 0 ? "ip6" : "ip";
  }
  function buildRule() {
    var direct = byName("edit_direct");
    if (direct && direct.checked) return;
    var parts = [];

    var iif = ifaceVal("iif");
    if (iif) parts.push("iif \"" + escapeNft(iif) + "\"");
    var oif = ifaceVal("oif");
    if (oif) parts.push("oif \"" + escapeNft(oif) + "\"");

    var saddr = val("saddr");
    if (saddr) parts.push(guessFamily(saddr) + " saddr " + saddr);
    var daddr = val("daddr");
    if (daddr) parts.push(guessFamily(daddr) + " daddr " + daddr);

    var proto = val("proto");
    var sport = val("sport");
    var dport = val("dport");
    var icmpType = val("icmp_type");
    if (!proto && (sport || dport)) {
      proto = "tcp";
    }

    var l4proto = "";
    var portProto = "";
    if (proto && (proto === "tcp" || proto === "udp")) {
      portProto = proto;
      if (!sport && !dport) {
        l4proto = proto;
      }
    }
    else if (proto) {
      l4proto = proto;
    }
    if (l4proto) {
      parts.push("meta l4proto " + l4proto);
    }
    if (sport && portProto) parts.push(portProto + " sport " + sport);
    if (dport && portProto) parts.push(portProto + " dport " + dport);

    if (proto === "icmp" && icmpType) parts.push("icmp type " + icmpType);
    if (proto === "icmpv6" && icmpType) parts.push("icmpv6 type " + icmpType);
    if (!proto && icmpType) {
      parts.push("meta l4proto icmp");
      parts.push("icmp type " + icmpType);
    }

    var tcpFlags = val("tcp_flags");
    var tcpMask = val("tcp_flags_mask");
    if (tcpFlags) {
      if (tcpMask) parts.push("tcp flags & " + tcpMask + " == " + tcpFlags);
      else parts.push("tcp flags " + tcpFlags);
    }

    var ctState = val("ct_state");
    if (ctState) parts.push("ct state " + ctState);

    var limitRate = val("limit_rate");
    var limitBurst = val("limit_burst");
    if (limitRate) {
      var lim = "limit rate " + limitRate;
      if (limitBurst) {
        lim += " burst " + limitBurst;
        if (isNumeric(limitBurst)) lim += " packets";
      }
      parts.push(lim);
    }

    var logBox = byName("log");
    var logEnabled = logBox && logBox.checked;
    var logPrefix = val("log_prefix");
    var logLevel = val("log_level");
    if (logEnabled || logPrefix || logLevel) {
      var lp = ["log"];
      if (logPrefix) lp.push("prefix \"" + escapeNft(logPrefix) + "\"");
      if (logLevel) lp.push("level " + logLevel);
      parts.push(lp.join(" "));
    }

    var counter = byName("counter");
    if (counter && counter.checked) parts.push("counter");

    var action = val("action");
    var jump = val("jump");
    var go = val("goto");
    if (action === "jump" && jump) parts.push("jump " + jump);
    else if (action === "goto" && go) parts.push("goto " + go);
    else if (action && action !== "jump" && action !== "goto") parts.push(action);

    var comment = val("comment");
    if (comment) parts.push("comment \"" + escapeNft(comment) + "\"");

    var extra = val("raw_extra");
    if (extra) parts.push(extra);

    var raw = parts.join(" ").replace(/^\s+|\s+$/g, "");
    var rawEl = byName("raw_rule");
    if (rawEl) rawEl.value = raw;
  }

  function toggleDirect() {
    var direct = byName("edit_direct");
    var on = direct && direct.checked;
    var form = direct ? direct.form : document.forms[0];
    if (!form) return;
    var els = form.querySelectorAll("input, select, textarea");
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.name === "edit_direct" || el.name === "raw_rule") continue;
      if (el.type === "hidden" || el.type === "submit" || el.type === "button") continue;
      el.disabled = on;
    }
    var rawEl = byName("raw_rule");
    if (rawEl) rawEl.readOnly = !on;
    if (!on) buildRule();
  }

  function bind() {
    var direct = byName("edit_direct");
    var form = direct ? direct.form : document.forms[0];
    if (!form) return;
    var els = form.querySelectorAll("input, select, textarea");
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.name === "raw_rule") continue;
      if (el.name === "edit_direct") {
        el.addEventListener("change", toggleDirect);
        continue;
      }
      el.addEventListener("input", buildRule);
      el.addEventListener("change", buildRule);
    }
    toggleDirect();
    buildRule();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
</script>
EOF

&ui_print_footer("index.cgi?table=$in{'table'}", $text{'index_return'});
