package Text::Treesitter::Bash::Security::Rule::DangerousFlags;
# ABSTRACT: Detect dangerous flag combinations in commands
our $VERSION = '0.006';
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

Only fires for commands whose flags actually mean mass destruction.
C<ls -rf> would technically match the force+recursive pattern but is
benign, so the rule is gated on a per-command allowlist (rm, mv, cp,
find, chmod, chown, rsync, tar, ...).

Short flags are matched case-insensitively so C<-fR>, C<-Fr>,
C<-FR>, C<-RF> are all recognised.

=head1 EXAMPLES

    rm -rf /tmp/x              -> high (DangerousFlags)
    rm --force --recursive /x  -> high (DangerousFlags)
    rm -fR /tmp/x              -> high (DangerousFlags)
    rm -r /tmp/x               -> (no issue)
    rm -f /tmp/x               -> (no issue)
    ls -rf                     -> (no issue — ls is not destructive)

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

# Commands for which `-r`/`-R` + force actually mean "destroy
# recursively". Anything outside this list will not be flagged even if
# it carries the same flag combination.
my %DESTRUCTIVE_COMMANDS = map { $_ => 1 } qw(
  rm
  mv
  cp
  find
  chmod
  chown
  chgrp
  rsync
  tar
  zip
  unzip
  git
);

# Per-flag metadata used to detect a dangerous combination. Keys are
# lowercased for case-insensitive short-flag matching.
my %DANGEROUS_FLAGS = (
  '-r'          => { kind => 'recursive', message => 'Recursive flag' },
  '--recursive' => { kind => 'recursive', message => 'Recursive flag' },
  '-f'          => { kind => 'force',     message => 'Force flag' },
  '--force'     => { kind => 'force',     message => 'Force flag' },
);

# Split a short-flag token like "-rf" / "-fR" into ["-r", "-f"] for
# de-composed matching. Returns the empty list for non-flag tokens and
# long flags. Lowercases each letter so the lookup table can be
# case-insensitive.
sub _decompose_short_flag {
  my ($arg) = @_;
  return () unless defined $arg && $arg =~ m/^-[A-Za-z]/ && $arg !~ m/^--/;
  return map { "-" . lc $_ } split //, substr($arg, 1);
}

# Normalise a long-flag token to lowercase for case-insensitive
# matching.
sub _normalise_flag {
  my ($arg) = @_;
  return $arg unless defined $arg;
  return lc $arg if $arg =~ m/^--/;
  return $arg;
}

sub check {
  my ( $class, $command ) = @_;

  my $name = $command->{command} // '';
  my $argv = $command->{argv} // [];

  # Gate on command whitelist (2.5.2).
  return unless $DESTRUCTIVE_COMMANDS{$name};

  my $has_force = 0;
  my $has_recursive = 0;

  for my $arg (@$argv) {
    next if ref $arg;

    # Match the full token first (handles --recursive, --force, "-r" alone,
    # "-f" alone). Then decompose short flags so "-rf" / "-fR" / "-RF" are
    # recognised as force + recursive.
    for my $cand ( _normalise_flag($arg), _decompose_short_flag($arg) ) {
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
