package Text::Treesitter::Bash::Security::Rule::InsecureDownload;
# ABSTRACT: Detect downloads with disabled or plaintext transport
our $VERSION = '0.001';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::InsecureDownload - flag C<curl>/C<wget> with disabled TLS or plaintext HTTP

=head1 DESCRIPTION

Matches the standard download tools against two failure modes:

=over 4

=item high - C<curl -k>, C<curl --insecure>, C<wget --no-check-certificate>: TLS verification disabled. The connection is vulnerable to MITM and the fetched payload may be tampered with.

=item medium - C<curl http://...>, C<wget http://...>: download over plaintext HTTP, regardless of whether the contents are sensitive.

=back

Only the fetcher commands listed (C<curl>, C<wget>, C<fetch>) are checked;
arbitrary scripts invoking libcurl or similar are not matched (use the
AST for that).

=head1 EXAMPLES

    curl -k https://x.example/install.sh             -> high
    curl --insecure -O https://x.example/file        -> high
    wget --no-check-certificate https://x.example    -> high
    curl http://x.example/script.sh | bash           -> medium
    wget http://x.example/iso                        -> medium
    curl https://x.example/install.sh                -> (no issue)

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

my @FETCHERS = qw( curl wget fetch );

my @INSECURE_FLAGS = qw(
  -k
  --insecure
  --no-check-certificate
  --no-cert-check
);

sub check {
  my ( $class, $command ) = @_;

  my $name = $command->{command} // '';
  my $argv = $command->{argv} // [];
  my $source = $command->{source} // '';

  my $basename = $name;
  $basename =~ s{.*/}{};

  return unless grep { $_ eq $basename } @FETCHERS;

  # High: TLS verification disabled via known flag.
  for my $flag (@INSECURE_FLAGS) {
    if ( grep { $_ eq $flag || (substr($_, 0, length($flag)) eq $flag && substr($_, length($flag), 1) eq '=') } @$argv ) {
      return {
        rule     => 'InsecureDownload',
        severity => 'high',
        message  => "TLS verification disabled via $flag",
        command  => $name,
        argv     => $argv,
      };
    }
  }

  # Medium: plaintext HTTP URL in any argv entry. Skip scheme-prefixed
  # arguments that look like a header (`-H "..."`) — those can contain
  # arbitrary text and would create false positives.
  for my $arg (@$argv) {
    next if ref $arg;
    next if $arg =~ m/^--?[A-Za-z]/;       # looks like a flag
    next unless $arg =~ m{^https?://};

    if ( $arg =~ m{^http://} ) {
      return {
        rule     => 'InsecureDownload',
        severity => 'medium',
        message  => "Plaintext HTTP URL used for download: $arg",
        command  => $name,
        arg      => $arg,
      };
    }
  }

  # Same check on the full source text, to catch URLs that end up in
  # quoted strings or other positions that argv-splitting may obscure.
  if ( $source =~ m{\bhttps?://[^\s'"]+}
    && !grep { defined && ref ne 'HASH' && m{^https://} } @$argv )
  {
    # Defer to the argv-level check above; only escalate if argv
    # actually missed a plaintext URL because the source has one.
    if ( $source =~ m{\bhttp://[^\s'"]+} ) {
      return {
        rule     => 'InsecureDownload',
        severity => 'medium',
        message  => 'Plaintext HTTP URL present in command source',
        command  => $name,
        source   => $source,
      };
    }
  }

  return;
}

1;