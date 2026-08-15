package Text::Treesitter::Bash::Security::Rule::DangerousExpansion;
# ABSTRACT: Detect dangerous parameter-expansion forms (CVE-2026-29783 class)
our $VERSION = '0.003';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::DangerousExpansion - detect C<${!var}>, C<${var@P}>, nested C<$()> in C<${}>

=head1 DESCRIPTION

Detects parameter-expansion forms that have historically been
exploitable vectors for code execution in AI-agent bash pipelines,
most recently as L<CVE-2026-29783|https://github.com/advisories/GHSA-g8r9-g2v8-jv6f>
(GitHub Copilot CLI, CVSS 7.1):

=over 4

=item C<${!var}> — indirect variable expansion. Resolves C<var> then expands the variable named by its value.

=item C<${var@P}> — prints variables as shell-executable statements. C<@P> is the "print as shell input" operator.

=item C<${var=...}> — assignment-on-expansion. When the variable is unset, assigns the value and expands to it.

=item C<${$()}> / C<${${...}}> — command substitution or nested expansion inside the parameter name.

=back

All four are flagged as C<high>.

=head1 EXAMPLES

    echo "${!HOME}"           -> high
    eval "${PATH@P}"          -> high
    : "${X=$(rm -rf $HOME)}"  -> high

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

sub check {
  my ( $class, $command ) = @_;

  my $source = $command->{source} // '';
  my @issues;

  if ( $source =~ m/\$\{!/ ) {
    push @issues, {
      rule     => 'DangerousExpansion',
      severity => 'high',
      message  => "Indirect variable expansion: \${!name}",
      command  => $command->{command},
      source   => $source,
    };
  }

  if ( $source =~ m/\$\{[^{}]*@[QP]\}/ ) {
    push @issues, {
      rule     => 'DangerousExpansion',
      severity => 'high',
      message  => 'Expansion prints as shell input: ${var@P/Q}',
      command  => $command->{command},
      source   => $source,
    };
  }

  if ( $source =~ m/\$\{[^{}]*=[^{}]*\}/ ) {
    push @issues, {
      rule     => 'DangerousExpansion',
      severity => 'high',
      message  => "Assignment-on-expansion: \${var=value}",
      command  => $command->{command},
      source   => $source,
    };
  }

  if ( $source =~ m/\$\{\$\(/ ) {
    push @issues, {
      rule     => 'DangerousExpansion',
      severity => 'high',
      message  => "Command substitution nested in parameter expansion: \${\$(...)}",
      command  => $command->{command},
      source   => $source,
    };
  }

  return @issues;
}

1;
