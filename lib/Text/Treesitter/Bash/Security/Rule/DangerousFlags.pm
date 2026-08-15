package Text::Treesitter::Bash::Security::Rule::DangerousFlags;
# ABSTRACT: Detect dangerous flag combinations in commands
our $VERSION = '0.005';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::DangerousFlags - detect high-blast-radius flag combos

=head1 DESCRIPTION

Flags C<rm -rf>, C<rm --force --recursive> (or any force-flag combined
with a recursive flag) as C<high>. The intent is to catch "delete a
lot of stuff without confirmation" patterns regardless of argument
shape. Individual flags without the combination are not flagged.

=head1 EXAMPLES

    rm -rf /tmp/x              -> high (DangerousFlags)
    rm --force --recursive /x  -> high (DangerousFlags)
    rm -r /tmp/x               -> (no issue)
    rm -f /tmp/x               -> (no issue)

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

# Per-flag metadata used to detect a dangerous combination. Long flags
# are matched verbatim; short flags are matched against both the full
# token (e.g. "-rf") and the de-composed letters (e.g. "-r" inside "-rf")
# so that combined flags work without being enumerated.
my %DANGEROUS_FLAGS = (
  '-r'          => { kind => 'recursive', message => 'Recursive flag' },
  '-R'          => { kind => 'recursive', message => 'Recursive flag' },
  '--recursive' => { kind => 'recursive', message => 'Recursive flag' },
  '-f'          => { kind => 'force',     message => 'Force flag' },
  '--force'     => { kind => 'force',     message => 'Force flag' },
);

# Split a short-flag token like "-rf" into ["-r", "-f"] for de-composed
# matching. Returns the empty list for non-flag tokens and long flags.
sub _decompose_short_flag {
  my ($arg) = @_;
  return () unless defined $arg && $arg =~ m/^-[A-Za-z]/ && $arg !~ m/^--/;
  return map { "-$_" } split //, substr($arg, 1);
}

sub check {
  my ( $class, $command ) = @_;

  my $name = $command->{command} // '';
  my $argv = $command->{argv} // [];

  my $has_force = 0;
  my $has_recursive = 0;

  for my $arg (@$argv) {
    next if ref $arg;

    # Match the full token first (handles --recursive, --force, "-r" alone,
    # "-f" alone). Then decompose short flags so "-rf" / "-fR" / "-RF" are
    # recognized as force + recursive.
    for my $cand ( $arg, _decompose_short_flag($arg) ) {
      my $info = $DANGEROUS_FLAGS{$cand};
      next unless $info;

      $has_force     = 1 if $info->{kind} eq 'force';
      $has_recursive = 1 if $info->{kind} eq 'recursive';
    }
  }

  if ( $has_force && $has_recursive ) {
    return {
      rule     => 'DangerousFlags',
      severity => 'high',
      message  => 'Dangerous combination: force + recursive flag (likely mass delete)',
      command  => $name,
      argv     => $argv,
    };
  }

  return;
}

1;
