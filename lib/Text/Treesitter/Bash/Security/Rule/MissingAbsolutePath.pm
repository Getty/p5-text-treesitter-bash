package Text::Treesitter::Bash::Security::Rule::MissingAbsolutePath;
# ABSTRACT: Detect commands without absolute paths
our $VERSION = '0.004';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::MissingAbsolutePath - flag commands invoked without absolute paths

=head1 DESCRIPTION

Reports commands whose name contains no C</>, does not start with
C<./> or C<../>, is not in a curated allowlist of common system
binaries (C<ls>, C<cat>, C<rm>, ...), and does not start with an
identifier-like character. Severity is C<low> - this is mostly a
"prefer full path" lint for AI-generated shell.

=head1 EXAMPLES

    /usr/bin/rm -rf /tmp/x   -> not flagged (absolute)
    ./script.sh              -> not flagged (explicit relative)
    ../bin/cmd               -> not flagged (explicit relative)
    cmd/subcmd               -> low (non-trivial relative path)
    rm -rf /tmp/x            -> not flagged (in allowlist)
    weirdtool foo bar        -> low (MissingAbsolutePath)
    1foo bar                 -> not flagged (not identifier-shaped)

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

my %KNOWN_COMMANDS = map { $_ => 1 } qw(
  ls cat rm cp mv mkdir rmdir chmod chown find grep sed awk
  tar zip unzip curl wget ssh scp git docker kubectl helm
  perl python ruby node npm pip cargo go make gcc clang
  ps kill pkill killall pgrep top htop free df du
  date cal uptime uname whoami id env printenv
  less more head tail sort uniq cut tr wc diff patch
  gzip bzip2 xz zcat
  apt apt-get yum dnf brew pacman
  sudo doas su
  jq yq sed awk xmllint
);

my %SHELL_BUILTINS = map { $_ => 1 } qw(
  . : [
  alias bg bind break builtin caller cd command compgen complete
  declare dirs disown echo enable eval exec exit export false fc
  fg getopts hash help history jobs kill local logout mapfile popd
  printf pushd pwd read readonly return set shift shopt source
  suspend test times trap true type typeset ulimit umask unalias
  unset wait
);

sub check {
  my ( $class, $command ) = @_;

  my $name = $command->{command} // '';

  # Absolute paths (C</usr/bin/cmd>) — caller has been explicit.
  return if $name =~ m{^/};
  # Explicit relative paths (C<./script.sh>, C<../bin/cmd>) — relative
  # to cwd, intentional.
  return if $name =~ m{^\./} || $name =~ m{^\.\./};

  # Anything else with a slash (e.g. C<cmd/subcmd>, C<foo/bar>) is a
  # non-trivial relative path that bypasses the allowlist by virtue of
  # looking like an absolute path. Flag it.
  if ( $name =~ m{/} ) {
    return {
      rule     => 'MissingAbsolutePath',
      severity => 'low',
      message  => "Command '$name' used without absolute path",
      command  => $name
    };
  }

  return if exists $KNOWN_COMMANDS{$name};
  return if exists $SHELL_BUILTINS{$name};

  # Names that do not look like identifiers (start with a digit, contain
  # characters that aren't valid in a command word) are syntactic
  # constructs, not real command names — do not flag them.
  return if $name !~ m{^[a-zA-Z_][a-zA-Z0-9_+\-.]*\z};

  return {
    rule     => 'MissingAbsolutePath',
    severity => 'low',
    message  => "Command '$name' used without absolute path",
    command  => $name
  };
}

1;