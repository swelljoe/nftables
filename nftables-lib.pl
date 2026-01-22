# nftables-lib.pl
# Functions for reading and writing nftables rules

BEGIN { push(@INC, ".."); };
use WebminCore;
use strict;
use warnings;
our (%config, $module_config_directory);
&init_config();

# get_nftables_save([file])
# Returns a list of tables and their chains/rules
sub get_nftables_save
{
my ($file) = @_;
my $cmd = $config{'nft_cmd'} || &has_command("nft");
if (!$file) {
    if ($config{'direct'}) {
        $file = "$cmd list ruleset |";
    } else {
        $file = $config{'save_file'} || "$module_config_directory/nftables.conf";
    }
}
return ( ) if (!$file);

my @rv;
my $table;
my $chain;
my $lnum = 0;
my $content;
open(my $fh, $file);
$content = do { local $/; <$fh> };
close($fh);

my @lines = split /\r?\n/, $content;
for(my $i=0; $i<@lines; $i++) {
    my $line = $lines[$i];
    $lnum++;
    $line =~ s/#.*$//; # Ignore comments for now
    
    if ($line =~ /^table\s+(\S+)\s+(\S+)\s+\{/) {
        # Start of a table
        $table = { 'name' => $2,
                   'family' => $1,
                   'line' => $lnum,
                   'rules' => [ ],
                   'chains' => { } };
        push(@rv, $table);
        $chain = undef;
    }
    elsif ($line =~ /^\s*chain\s+(\S+)\s+\{/) {
        # Start of a chain
        if ($table) {
            $chain = $1;
            $table->{'chains'}->{$chain} = { };
            
            # Look at next line for chain definition
            if ($lines[$i+1] =~ /^\s*type\s+(\S+)\s+hook\s+(\S+)\s+priority\s+([a-zA-Z0-9_-]+);\s+policy\s+(\S+);/) {
                $table->{'chains'}->{$chain}->{'type'} = $1;
                $table->{'chains'}->{$chain}->{'hook'} = $2;
                $table->{'chains'}->{$chain}->{'priority'} = $3;
                $table->{'chains'}->{$chain}->{'policy'} = $4;
                $i++; # Skip next line
            }
        }
    }
    elsif ($line =~ /^\s*(.*?)$/ && $table && $chain && $1 ne "}") {
        # A rule
        my $rule_str = $1;
        if ($rule_str =~ /\S/) {
           my $rule = {
               'text' => $rule_str,
               'chain' => $chain,
               'index' => scalar(@{$table->{'rules'}}),
               'line' => $lnum
           };
           if ($rule_str =~ /\bcomment\s+"((?:\\.|[^"\\])*)"/) {
               my $c = $1;
               $c =~ s/\\"/"/g;
               $c =~ s/\\\\/\\/g;
               $rule->{'comment'} = $c;
           }
           if ($rule_str =~ /(\S+)\s+dport\s+(\d+)/) {
               $rule->{'proto'} = $1;
               $rule->{'dport'} = $2;
           }
           if ($rule_str =~ /\biif\s+"([^"]+)"/) {
               $rule->{'iif'} = $1;
           }
           elsif ($rule_str =~ /\biif\s+(\S+)/) {
               $rule->{'iif'} = $1;
           }
           if ($rule_str =~ /\boif\s+"([^"]+)"/) {
               $rule->{'oif'} = $1;
           }
           elsif ($rule_str =~ /\boif\s+(\S+)/) {
               $rule->{'oif'} = $1;
           }
           my @actions = ($rule_str =~ /\b(accept|drop|reject)\b/g);
           if (@actions) {
               $rule->{'action'} = $actions[-1];
           }
           push(@{$table->{'rules'}}, $rule);
        }
    }
}

return @rv;
}


# dump_nftables_save(@tables)
# Returns a string representation of the firewall rules
sub dump_nftables_save
{
my (@tables) = @_;
my $rv;
foreach my $t (@tables) {
    if ($t->{'family'}) {
        $rv .= "table $t->{'family'} $t->{'name'} {\n";
    } else {
        $rv .= "table $t->{'name'} {\n";
    }
    
    foreach my $c (keys %{$t->{'chains'}}) {
        my $chain = $t->{'chains'}->{$c};
        $rv .= "\tchain $c {\n";
        if ($chain->{'type'}) {
            $rv .= "\t\ttype $chain->{'type'} hook $chain->{'hook'} priority $chain->{'priority'}; policy $chain->{'policy'};\n";
        }
        
        # Add rules for this chain
        my @rules = sort { $a->{'index'} <=> $b->{'index'} } 
                 grep { ref($_) eq 'HASH' && $_->{'chain'} eq $c } @{$t->{'rules'}};
        foreach my $r (@rules) {
             $rv .= "\t\t$r->{'text'}\n";
        }
        $rv .= "\t}\n";
    }
    $rv .= "}\n";
}
return $rv;
}

# save_table(&table)
# Saves a single table to the save file or applies it
sub save_table
{
my ($table) = @_;
# Re-read all tables to ensure we have the full picture if we are overwriting the file
# But here we probably just want to update the specific table in the list of tables we have.
# Since we usually operate on a list of tables, we might need to pass the full list or 
# re-read the state. 
# For simplicity, we usually load all, modify one, and save all.
}

# save_configuration(@tables)
# Writes the configuration to the save file. If direct mode is on, applies it.
sub save_configuration
{
my (@tables) = @_;
my $out = &dump_nftables_save(@tables);
my $file = $config{'save_file'} || "$module_config_directory/nftables.conf";

# Write to file
&open_tempfile(my $fh, ">$file");
&print_tempfile($fh, $out);
&close_tempfile($fh);

if ($config{'direct'}) {
    return &apply_restore($file);
}
return undef;
}

# apply_restore([file])
# Applies the configuration from the save file
sub apply_restore
{
my ($file) = @_;
$file ||= $config{'save_file'} || "$module_config_directory/nftables.conf";
my $cmd = $config{'nft_cmd'} || &has_command("nft");
my $out = &backquote_logged("$cmd -f $file 2>&1");
if ($?) {
    return "<pre>$out</pre>";
}
return undef;
}

# describe_rule(&rule)
sub describe_rule
{
my ($r) = @_;
my $desc;
if ($r->{'proto'} && $r->{'dport'} && $r->{'action'}) {
    $desc = &text('index_rule_desc', $r->{'action'}, $r->{'proto'}, $r->{'dport'});
}
elsif ($r->{'iif'} && $r->{'oif'} && $r->{'action'}) {
    $desc = &text('index_rule_desc4', $r->{'action'}, $r->{'iif'}, $r->{'oif'});
}
elsif ($r->{'iif'} && $r->{'action'}) {
    $desc = &text('index_rule_desc3', $r->{'action'}, $r->{'iif'});
}
elsif ($r->{'oif'} && $r->{'action'}) {
    $desc = &text('index_rule_desc2', $r->{'action'}, $r->{'oif'});
}
else {
    $desc = &html_escape($r->{'text'});
}
return $desc;
}

# interface_choice(name, value, blanktext)
# Returns HTML for an interface chooser menu
sub interface_choice
{
my ($name, $value, $blanktext) = @_;
if (&foreign_check("net")) {
    &foreign_require("net", "net-lib.pl");
    return &net::interface_choice($name, $value, $blanktext, 0, 1);
}
else {
    return &ui_textbox($name, $value, 20);
}
}

1;
