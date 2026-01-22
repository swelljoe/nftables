#!/usr/bin/perl
# index.cgi
# Display current nftables configuration

require './nftables-lib.pl';
use strict;
use warnings;
our (%in, %text, %config);
&ReadParse();
&ui_print_header(undef, $text{'index_title'}, "", "intro", 1, 1);

# Check for nft command
my $cmd = $config{'nft_cmd'} || &has_command("nft");
if (!$cmd) {
    print &text('index_ecommand', "<tt>nft</tt>");
    &ui_print_footer("/", $text{'index'});
    exit;
}

# Check if kernel supports it (basic check)
my $out = &backquote_command("$cmd list ruleset 2>&1");
if ($? && $out !~ /no ruleset/i) {
    # If it fails and not just empty
    print &text('index_ekernel', "<pre>$out</pre>");
    &ui_print_footer("/", $text{'index'});
    exit;
}

# Load tables
my @tables = &get_nftables_save();

if (!@tables) {
    print "<b>$text{'index_none'}</b><p>\n";
    print &ui_buttons_start();
    print &ui_buttons_row("setup.cgi", $text{'index_setup'}, $text{'index_setupdesc'});
    print &ui_buttons_end();
} else {
    # Select table
    if (!defined($in{'table'}) || $in{'table'} !~ /^\d+$/ ||
        $in{'table'} > $#tables) {
        $in{'table'} = 0;
    }
    my @table_opts;
    for (my $i = 0; $i <= $#tables; $i++) {
        my $t = $tables[$i];
        push(@table_opts, [ $i, $t->{'family'}." ".$t->{'name'} ]);
    }

    print &ui_form_start("index.cgi");
    print &text('index_change')," ";
    print &ui_select("table", $in{'table'}, \@table_opts, 1, 0, 1);
    print &ui_form_end();

    # Identify current table
    my $curr = $tables[$in{'table'}];

    if ($curr) {
        # Show chains and rules
        print &ui_hr();
        print &ui_columns_start(
            [ $text{'index_chain_col'}, $text{'index_type'},
              $text{'index_hook'}, $text{'index_priority'},
              $text{'index_policy_col'}, $text{'index_rules'} ], 100);

        foreach my $c (sort keys %{$curr->{'chains'}}) {
            my $chain_def = $curr->{'chains'}->{$c} || { };
            my $policy = $chain_def->{'policy'};
            my $policy_label = $policy ?
                ($text{'index_policy_'.lc($policy)} || uc($policy)) : "-";
            my @rules = grep { $_->{'chain'} eq $c } @{$curr->{'rules'}};
            my $rules_html;
            if (@rules) {
                my @rows;
                foreach my $r (@rules) {
                    my $desc = &describe_rule($r);
                    push(@rows, &ui_link(
                        "edit_rule.cgi?table=$in{'table'}&chain=".
                        &urlize($c)."&idx=$r->{'index'}",
                        $desc));
                }
                $rules_html = join("<br>", @rows);
            } else {
                $rules_html = "<i>$text{'index_rules_none'}</i>";
            }
            $rules_html .= "<br>".
                &ui_link("edit_rule.cgi?table=$in{'table'}&chain=".
                         &urlize($c)."&new=1", $text{'index_radd'});

            print &ui_columns_row([
                $c,
                $chain_def->{'type'} || "-",
                $chain_def->{'hook'} || "-",
                defined($chain_def->{'priority'}) ? $chain_def->{'priority'} : "-",
                $policy_label,
                $rules_html
            ]);
        }
        print &ui_columns_end();
    }
}

print &ui_hr();
print &ui_buttons_start();
print &ui_buttons_row("apply.cgi", $text{'index_apply'}, $text{'index_applydesc'});
print &ui_buttons_end();

&ui_print_footer("/", $text{'index'});
