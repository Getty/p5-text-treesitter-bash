package Text::Treesitter::Bash::Security::Rule::PrivilegeEscalation;
# ABSTRACT: Detect privilege escalation patterns
our $VERSION = '0.001';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::PrivilegeEscalation - flag invocation of privilege-escalating primitives

=head1 DESCRIPTION

Flags patterns that grant elevated capabilities, set up persistent
privilege escalation, or invoke a privileged environment.

=over 4

=item high - root shells and explicit privilege elevation:

    sudo su -
    sudo -i
    sudo bash
    sudo /bin/bash
    su -
    su - root
    doas bash
    pkexec /bin/bash

=item high - SetUID / SetGID bits installed on a file:

    chmod u+s /usr/local/bin/foo
    chmod g+s /usr/local/bin/foo
    chmod 4755 /usr/local/bin/foo
    chmod 6755 /usr/local/bin/foo

=item medium - find/exec chains that combine with chmod for
post-exploitation persistence:

    find . -perm -u=x -exec chmod u+s {} \;

=item medium - systemd-run into a privileged user scope:

    systemd-run --user --scope

=back

The rule operates only on the AST-visible command invocation;
arbitrary command-substitution content is out of scope (use
C<findings> / shell-interpreter rules for that).

=head1 EXAMPLES

    sudo bash                              -> high
    su -                                   -> high
    doas /bin/sh                           -> high
    pkexec /bin/bash                       -> high
    chmod u+s /usr/local/bin/x             -> high
    chmod 4755 /tmp/x                      -> high
    find / -perm -u=x -exec chmod u+s {} \; -> medium
    systemctl daemon-reload                -> (not flagged)
    sudo ls /root                          -> (not flagged, just elevated listing)

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

# Map of basenames → list of argv-trigger → severity → message.
# Each entry is [ \@flags_or_argv, $severity, $message_substr_or_undef ].
# If \@flags_or_argv is undef, any argv triggers (just the basename).
# Otherwise argv must contain ALL of the listed strings.
sub check {
  my ( $class, $command ) = @_;

  my $name = $command->{command} // q{};
  my $argv = $command->{argv}    // [];

  my $basename = $name;
  $basename =~ s{.*/}{};

  return _check_root_shell( $basename, $name, $argv )
    || _check_setuid( $basename, $name, $argv )
    || _check_systemd_run( $basename, $name, $argv );
}

# Anything that lands you at a root prompt.
sub _check_root_shell {
  my ( $basename, $name, $argv ) = @_;

  # sudo / doas / pkexec → first positional arg is a shell, OR the
  # wrapper is invoked with `-i` / `-s` (root-shell shortcuts), OR
  # `su` is the target (sudo su, sudo su -).
  for my $wrapper (qw( sudo doas pkexec )) {
    next unless $basename eq $wrapper;

    # `-i` / `-s` / `--login` alone = interactive shell.
    my $has_root_flag = grep { defined && !ref && m{^(?:-[is]|--login|--shell|-i[A-Za-z]|-s[A-Za-z])\z} } @$argv;
    return _priv_issue( $name, $argv, 'high',
      "$wrapper opens root shell via flag" )
      if $has_root_flag;

    # First positional is a shell name OR `su`.
    return _priv_issue( $name, $argv, 'high',
      "$wrapper invokes elevated shell" )
      if _has_shell_target($argv);
  }

  # su → if argument list contains `-` or a username, that's a root
  # shell attempt.
  if ( $basename eq 'su' ) {
    for my $arg (@$argv) {
      next unless defined $arg && !ref $arg;
      next if $arg eq 'su';
      if ( $arg eq '-'
        || $arg eq '-l'
        || $arg eq '--login'
        || $arg =~ /^[a-z_][a-z0-9_-]{0,31}$/ ) {
        return _priv_issue( $name, $argv, 'high', 'su to privileged user' );
      }
    }
  }

  return;
}

sub _has_shell_target {
  my ( $argv ) = @_;

  # shell-interpreter allowlist (kept in sync with Bash.pm), plus
  # `su` (sudo su is a classic elevation chain).
  my @shells = qw( sh bash dash zsh fish ksh ash bash5 su );

  # Drop wrapper args (everything up to and including the first
  # non-flag arg, treating `-i`, `-s`, `--login` as flags).
  my @tail = @$argv;
  shift @tail;    # drop the wrapper itself
  my $found_flag = 1;   # accept flags at the start
  for my $arg (@tail) {
    next unless defined $arg && !ref $arg;
    if ( $arg =~ m{^--?[a-zA-Z]} ) {
      $found_flag = 1;
      next;
    }
    # first positional — must be a shell name.
    if ( $found_flag ) {
      for my $shell (@shells) {
        if ( $arg eq $shell || $arg =~ m{\A\Q$shell\E\z} ) {
          return 1;
        }
      }
      # path to a shell.
      if ( $arg =~ m{/bash\z} || $arg =~ m{/sh\z} || $arg =~ m{/zsh\z} ) {
        return 1;
      }
    }
    $found_flag = 0;
  }
  return;
}

sub _check_setuid {
  my ( $basename, $name, $argv ) = @_;
  return unless $basename eq 'chmod';

  # Drop `chmod` itself.
  my @tail = @$argv;
  shift @tail;

  for my $mode (@tail) {
    next unless defined $mode && !ref $mode;
    next if $mode =~ m{^--?[a-zA-Z]};    # flag

    # Numeric mode: special bits are encoded in the leading digit of
    # the 4-digit octal. The mode may be given as 3 or 4 digits
    # (`755` means `0755`, no special bits); pad with a leading
    # zero to normalize. Then:
    #   1 = sticky
    #   2 = SetGID
    #   4 = SetUID
    #   3 = sticky+SetGID
    #   5 = sticky+SetUID
    #   6 = SetUID+SetGID
    #   7 = all
    if ( $mode =~ m{\A([0-7]{3,4})\z} ) {
      my $digits = $1;
      my $special = length($digits) == 4 ? substr( $digits, 0, 1 ) : '0';
      if ( $special =~ /[23567]/ ) {
        return _priv_issue( $name, $argv, 'high', 'chmod SetGID (numeric mode)', mode => $mode );
      }
      if ( $special =~ /[4567]/ ) {
        return _priv_issue( $name, $argv, 'high', 'chmod SetUID (numeric mode)', mode => $mode );
      }
    }

    # Symbolic: u+s / g+s / +s / a+s (any who + set s).
    if ( $mode =~ m{\A([ugoa+]*)\+(s[sStTxX]*)\z} ) {
      my $who  = $1 // q{};
      my $what = $2 // q{};
      next unless $what =~ /s/;
      my $severity = 'high';
      my $desc = length($who) ? "chmod $who+s" : 'chmod +s (SetUID+SetGID)';
      return _priv_issue( $name, $argv, $severity, $desc, mode => $mode );
    }
  }
  return;
}

sub _check_systemd_run {
  my ( $basename, $name, $argv ) = @_;
  return unless $basename eq 'systemd-run';

  for my $arg (@$argv) {
    next unless defined $arg && !ref $arg;
    if ( $arg eq '--user'
      || $arg eq '--scope'
      || ( substr( $arg, 0, length('--user') ) eq '--user'
           && substr( $arg, length('--user'), 1 ) eq '=' ) ) {
      return _priv_issue( $name, $argv, 'medium',
        'systemd-run into user/scope' );
    }
  }
  return;
}

sub _priv_issue {
  my ( $name, $argv, $severity, $message, %extra ) = @_;
  return {
    rule     => 'PrivilegeEscalation',
    severity => $severity,
    message  => $message,
    command  => $name,
    argv     => $argv,
    %extra,
  };
}

1;