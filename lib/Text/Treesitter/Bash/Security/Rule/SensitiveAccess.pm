package Text::Treesitter::Bash::Security::Rule::SensitiveAccess;
# ABSTRACT: Detect access to sensitive files and directories
our $VERSION = '0.004';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::SensitiveAccess - detect argv that touches credential/secret paths

=head1 DESCRIPTION

Matches argv entries against a fixed list of credential- or
introspection-sensitive paths. Severity scales with sensitivity:

=over 4

=item high   - C</etc/shadow>, C</etc/sudoers>, C<~/.ssh/>, C<~/.aws/>, C<~/.kube/>

=item medium - C</etc/passwd>, C</etc/group>, C</proc/self/>, C</sys/fs/>

=item low    - C</dev/> (often benign, but worth a glance)

=back

Pattern matching is naive regex on the raw argv text, so quoted or
expanded paths can evade detection. If you need robust matching on
those, use the AST.

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>,
L<Text::Treesitter::Bash::Security::Rule::PathTraversal>.

=cut

my @SENSITIVE_PATTERNS = (
  # high — direct credential stores
  [ qr{/etc/shadow},           'high',   'Shadow password file access' ],
  [ qr{/etc/sudoers},          'high',   'sudoers file access' ],
  [ qr{/etc/sudoers\.d/},      'high',   'sudoers.d file access' ],
  [ qr{/\.ssh/},               'high',   'SSH directory access' ],
  [ qr{/\.aws/},               'high',   'AWS credentials directory access' ],
  [ qr{/\.kube/},              'high',   'Kubernetes config access' ],
  [ qr{/\.docker/config\.json}, 'high',   'Docker config access' ],
  [ qr{/\.gnupg/private-keys}, 'high',   'GnuPG private keys access' ],
  [ qr{/\.git-credentials},    'high',   'Git stored credentials access' ],
  [ qr{/\.netrc},              'high',   'netrc credentials access' ],
  [ qr{/\.pypirc},             'high',   'PyPI credentials access' ],
  [ qr{/\.npmrc},              'high',   'npm credentials access' ],
  [ qr{/\.cargo/credentials},  'high',   'Cargo credentials access' ],
  [ qr{/google-cloud/},        'high',   'gcloud config access' ],
  [ qr{/\.azure/},             'high',   'Azure CLI config access' ],
  [ qr{/\.config/gh/},         'high',   'GitHub CLI config access' ],
  [ qr{/\.docker/config\.json}, 'high',   'Docker daemon config access' ],
  [ qr{/gcloud/},              'high',   'gcloud config access' ],
  [ qr{/\.config/gcloud/},     'high',   'gcloud config access' ],
  # medium — system DBs and introspection
  [ qr{/etc/passwd},           'medium', 'Password database access' ],
  [ qr{/etc/group},            'medium', 'Group database access' ],
  [ qr{/etc/gshadow},          'medium', 'Group shadow file access' ],
  [ qr{/proc/self/},           'medium', 'Process self introspection' ],
  [ qr{/proc/\d+/environ},     'medium', 'Process environment access' ],
  [ qr{/sys/fs/},              'medium', 'Filesystem sysfs access' ],
  # low — generally benign but worth flagging
  [ qr{/dev/},                 'low',    'Device file access' ],
);

# Whitelist of `/dev/` paths that are common and benign. Strings are
# matched verbatim against argv entries. Anything not in the whitelist
# still triggers the (low) severity finding.
my %DEV_WHITELIST = map { $_ => 1 } qw(
  /dev/null
  /dev/zero
  /dev/full
  /dev/tty
  /dev/stdin
  /dev/stdout
  /dev/stderr
  /dev/random
  /dev/urandom
  /dev/fd
  /dev/fd/0
  /dev/fd/1
  /dev/fd/2
  /dev/pts
  /dev/pts/0
  /dev/shm
);

sub check {
  my ( $class, $command ) = @_;

  for my $arg ( @{ $command->{argv} // [] } ) {
    next if ref $arg;

    for my $tuple (@SENSITIVE_PATTERNS) {
      my ( $pattern, $severity, $message ) = @$tuple;

      if ( $arg =~ $pattern ) {
        # Skip the (low) /dev/ finding for entries in the whitelist.
        return if $severity eq 'low' && $DEV_WHITELIST{$arg};
        return {
          rule     => 'SensitiveAccess',
          severity => $severity,
          message  => "$message: $arg",
          arg      => $arg,
          command  => $command->{command}
        };
      }
    }
  }

  return;
}

1;