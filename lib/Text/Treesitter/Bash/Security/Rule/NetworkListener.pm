package Text::Treesitter::Bash::Security::Rule::NetworkListener;
# ABSTRACT: Detect commands that open network listeners
our $VERSION = '0.001';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::NetworkListener - flag invocations that open inbound network listeners

=head1 DESCRIPTION

Flags commands that open a socket or otherwise expose an inbound service.
Useful for AI-agent pipelines where an attacker could attempt to plant
a listener that survives the agent's lifetime (or coexists with a
reverse-shell sink).

Forms detected:

=over 4

=item high - bare TCP listeners via C<nc> / C<ncat> / C<socat>:

    nc -l 4444
    nc -lk 4444
    ncat -l 4444
    socat TCP-LISTEN:4444,fork EXEC:/bin/sh
    socat TCP4-LISTEN:80,reuseaddr EXEC:cat

=item high - ssh tunnels / proxies:

    ssh -R 8080:internal:80 bastion
    ssh -D 1080 bastion

=item medium - one-liner web servers bound to all interfaces:

    python3 -m http.server 8000
    php -S 0.0.0.0:8000

=item low - one-liner web servers bound to localhost only:

    php -S 127.0.0.1:8000

=back

The walker exposes C<command> with path-stripping already applied, so
C</usr/bin/nc> and C<nc> both match.

=head1 EXAMPLES

    nc -l 4444                              -> high
    socat TCP-LISTEN:4444,fork EXEC:/bin/sh -> high
    ssh -R 8080:internal:80 bastion         -> high
    ssh -D 1080 bastion                      -> high
    python3 -m http.server 8000              -> medium
    php -S 0.0.0.0:8000                     -> medium
    php -S 127.0.0.1:8000                   -> low
    nc host 80 < file                       -> (not flagged; this is outbound)

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule::ReverseShellSink> for the
matching outbound side.

=cut

sub check {
  my ( $class, $command ) = @_;

  my $name   = $command->{command} // q{};
  my $argv   = $command->{argv}    // [];
  my $source = $command->{source}  // q{};

  my $basename = $name;
  $basename =~ s{.*/}{};

  return _check_nc( $basename, $name, $argv )
    || _check_socat( $basename, $name, $argv )
    || _check_ssh( $basename, $name, $argv )
    || _check_http_server( $basename, $name, $argv )
    || _check_tcp_listen_source( $basename, $name, $source );
}

sub _check_nc {
  my ( $basename, $name, $argv ) = @_;
  return unless $basename eq 'nc' || $basename eq 'ncat';

  for my $arg (@$argv) {
    next unless defined $arg && !ref $arg;
    # nc accepts -l, -lk, -lp, -lke, etc. — any flag starting with -l...
    # But NOT --listen (which we also want). And NOT --literal or
    # --linger (which begin with -l but have different semantics).
    next unless $arg eq '-l'
      || ( substr( $arg, 0, 2 ) eq '-l'
           && length($arg) > 2
           && substr( $arg, 2, 1 ) =~ /\A[a-zA-Z0-9]/ )
      || $arg eq '--listen'
      || ( substr( $arg, 0, length('--listen') ) eq '--listen'
           && length($arg) > length('--listen')
           && substr( $arg, length('--listen'), 1 ) eq '=' );
    return {
      rule     => 'NetworkListener',
      severity => 'high',
      message  => "$basename opened as network listener ($arg)",
      command  => $name,
      arg      => $arg,
    };
  }
  return;
}

sub _check_socat {
  my ( $basename, $name, $argv ) = @_;
  return unless $basename eq 'socat';

  for my $arg (@$argv) {
    next unless defined $arg && !ref $arg;
    for my $tok (qw( TCP-LISTEN TCP4-LISTEN TCP6-LISTEN )) {
      if ( $arg =~ /\A\Q$tok\E/ ) {
        return {
          rule     => 'NetworkListener',
          severity => 'high',
          message  => "socat $tok listener: $arg",
          command  => $name,
          arg      => $arg,
        };
      }
    }
  }
  return;
}

sub _check_ssh {
  my ( $basename, $name, $argv ) = @_;
  return unless $basename eq 'ssh';

  for my $arg (@$argv) {
    next unless defined $arg && !ref $arg;
    if ( $arg eq '-R' || $arg eq '-D' ) {
      return {
        rule     => 'NetworkListener',
        severity => 'high',
        message  => "ssh $arg opens a tunnel or proxy",
        command  => $name,
        arg      => $arg,
      };
    }
    # Combined flag form like -R1234 or -D1080.
    if ( length($arg) > 2
      && substr( $arg, 0, 2 ) eq '-R'
      && substr( $arg, 2, 1 ) =~ /\A[0-9]/ )
    {
      return {
        rule     => 'NetworkListener',
        severity => 'high',
        message  => "ssh $arg opens a tunnel or proxy",
        command  => $name,
        arg      => $arg,
      };
    }
    if ( length($arg) > 2
      && substr( $arg, 0, 2 ) eq '-D'
      && substr( $arg, 2, 1 ) =~ /\A[0-9]/ )
    {
      return {
        rule     => 'NetworkListener',
        severity => 'high',
        message  => "ssh $arg opens a tunnel or proxy",
        command  => $name,
        arg      => $arg,
      };
    }
  }
  return;
}

sub _check_http_server {
  my ( $basename, $name, $argv ) = @_;

  # Drop the leading command name to simplify matching on positional args.
  my @tail;
  for my $i ( 1 .. $#$argv ) {
    push @tail, $argv->[$i] // next;
  }

  my @joined = ( ' ', join( "\x00", @tail ), ' ' );

  # python -m http.server / python3 -m http.server / python2 -m SimpleHTTPServer
  if ( $basename eq 'python' || $basename eq 'python3' || $basename eq 'python2' ) {
    return _http_server_match(
      $name, $argv,
      tokens  => [ 'http.server', 'SimpleHTTPServer' ],
      default_severity => 'medium',
      label    => 'Python HTTP server',
    );
  }

  # php -S [addr:port]
  if ( $basename eq 'php' ) {
    for my $i ( 0 .. $#tail ) {
      next unless $tail[$i] eq '-S';
      my $addr = $tail[ $i + 1 ] // '';
      my $sev = 'low';
      if ( $addr =~ m{\A0\.0\.0\.0:} || $addr =~ m{\A\[?::\]?:} || $addr =~ m{\A\*:} ) {
        $sev = 'high';
      }
      elsif ( $addr =~ m{\A127\.0\.0\.1:|\Alocalhost:} ) {
        $sev = 'low';
      }
      else {
        $sev = 'medium';
      }
      return {
        rule     => 'NetworkListener',
        severity => $sev,
        message  => "PHP built-in web server (-S $addr)",
        command  => $name,
        arg      => '-S',
        address  => $addr,
      };
    }
    return;
  }

  # ruby -run -e httpd
  if ( $basename eq 'ruby' ) {
    # -run -e httpd is a single signature; require the triple to match.
    my $joined = ' ' . join( ' ', @tail ) . ' ';
    if ( index( $joined, ' -run -e httpd ' ) >= 0 ) {
      return {
        rule     => 'NetworkListener',
        severity => 'medium',
        message  => 'Ruby WEBrick httpd started',
        command  => $name,
        arg      => 'httpd',
      };
    }
    return;
  }

  # node / npx http-server
  if ( $basename eq 'node' || $basename eq 'npx' || $basename eq 'npm' ) {
    return _http_server_match(
      $name, $argv,
      tokens  => [ 'http-server', 'serve', 'live-server' ],
      default_severity => 'medium',
      label    => 'Node HTTP server',
    );
  }

  return;
}

sub _http_server_match {
  my ( $name, $argv, %opts ) = @_;

  my $tokens = $opts{tokens} // [];
  my $combined = $opts{require_combined};

  my @tail = @$argv;
  shift @tail;

  if ($combined) {
    my $joined = ' ' . join( "\x00", @tail ) . ' ';
    return unless index( $joined, ' ' . $combined . ' ' ) >= 0;
  }

  for my $tok (@$tokens) {
    for my $arg (@tail) {
      next unless defined $arg && !ref $arg;
      return {
        rule     => 'NetworkListener',
        severity => $opts{default_severity} // 'medium',
        message  => $opts{label} . ' started',
        command  => $name,
        arg      => $arg,
      } if $arg eq $tok || ( length($arg) > length($tok)
        && substr( $arg, 0, length($tok) ) eq $tok
        && substr( $arg, length($tok), 1 ) eq '=' );
    }
  }
  return;
}

sub _check_tcp_listen_source {
  my ( $basename, $name, $source ) = @_;
  return if $source =~ m{^\s*#};
  if ( $source =~ m{\b(?:TCP-LISTEN|TCP4-LISTEN|TCP6-LISTEN)\b} ) {
    return {
      rule     => 'NetworkListener',
      severity => 'high',
      message  => 'TCP-LISTEN token present in command source',
      command  => $name,
      source   => $source,
    };
  }
  return;
}

1;