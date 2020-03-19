#!/usr/bin/env perl
use strict;
use warnings;
use 5.30.0;

use XML::Twig;

my $svg_in_filename = 'CBC-decryption.svg';
my $svg_out_filename = 'CBC-decryption-optimized.svg';

my $parser = XML::Twig->new(
  pretty_print => 'indented'
); 
my $in_doc = $parser->parsefile($svg_in_filename);

remove_extra_tspans();
replace_group_labels_as_ids();
add_position_to_text_fields();

open my $in_fh, '>', $svg_out_filename or die $!;
$in_doc->print($in_fh);
close $in_fh;

run_svgo();

my $out_doc = $parser->parsefile($svg_out_filename);
add_style_element_back();

open my $out_fh, '>', $svg_out_filename;
$out_doc->print($out_fh);
close $out_fh;

sub remove_extra_tspans {
  my $xpath = '/svg/text';
  
  for my $text_element ($in_doc->get_xpath($xpath)) {
    if ($text_element->contains_a_single('tspan')) {
      my ($tspan_child) = $text_element->cut_children();
      $text_element->set_text($tspan_child->text_only());
    }
  }
}

sub replace_group_labels_as_ids {
  my $xpath = '/svg/g';
  my $group_keyname = 'inkscape:label';
  
  for my $group_element ($in_doc->get_xpath($xpath)) {
    next unless exists($group_element->atts()->{$group_keyname});

    my $label = $group_element->atts()->{$group_keyname};

    $group_element->set_id($label);
    $group_element->set_class("group");
  }
}

sub add_position_to_text_fields {
  my $xpath = '/svg/g';
  my @group_prefixes = qw( plaintext decrypted key iv ciphertext );
  my $group_regex = join('|', @group_prefixes);
  
  for my $group_element ($in_doc->get_xpath($xpath)) {
    next unless $group_element->id =~ /^($group_regex)/;

    my $pos = 0;
    for my $text_element ($group_element->children('text')) {
      $text_element->set_id($group_element->id . '-' . $pos);
      $pos+=1;

      # kludge, slipping this in here.
      $text_element->del_att('font-size', 'font-weight', 'letter-spacing', 'style', 'word-spacing');
    }
  }
}

sub run_svgo {
  my $svgo_config_filename = '.svgo.yml';
  qx(npx svgo -i $svg_out_filename --config $svgo_config_filename);
}

sub add_style_element_back {
  $out_doc->root->insert_new_elt('first_child', 'style', {}, 
q|
.group > text {
  font-size: 5.27px;
  font-weight: 400;
  letter-spacing: 0;
  font-weight: 400;
  line-height:1.25;
  font-family:sans-serif;
  word-spacing:0;
  stroke-width:0.99
}
|);
}
