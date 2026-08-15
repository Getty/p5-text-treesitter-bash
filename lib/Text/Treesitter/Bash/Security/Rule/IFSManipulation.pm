package Text::Treesitter::Bash::Security::Rule::IFSManipulation;
# ABSTRACT: Detect IFS manipulation that breaks word-splitting invariants
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::IFSManipulation - detect IFS overrides that break word-splitting

=head1 DESCRIPTION

Detects assignments to C<IFS> or uses of C<$IFS> in tokens that look
like a separator definition (e.g. C<IFS=$' \t\n'>, C<IFS=,
$'\x20'>, C<export IFS=>). IFS manipulation is the classic trick used
to evade shell-quoting-based command-injection audits.

    IFS=$' \t\n' read -r line < file       -> high
    IFS=, read -d, -ra parts <<< "a,b,c"  -> high
    export IFS=; for x in $*              -> high

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

sub check {
  my ( $class, $command ) = @_;

  my $source = $command->{source} // '';
  return unless $source =~ m{\bIFS\b};

  # Assignments: IFS=, IFS=..., export IFS=...
  if ( $source =~ m{\b(?:export\s+)?IFS\s*=} ) {
    return {
      rule     => 'IFSManipulation',
      severity => 'high',
      message  => "IFS override: '$source'",
      command  => $command->{command},
      source   => $source,
    };
  }

  # $IFS expansion followed by a delimiter character:
  if ( $source =~ m{\$IFS[^a-zA-Z0-9_]} ) {
    return {
      rule     => 'IFSManipulation',
      severity => 'medium',
      message  => "Possible IFS-bound expansion: '$source'",
      command  => $command->{command},
      source   => $source,
    };
  }

  return;
}

1;
