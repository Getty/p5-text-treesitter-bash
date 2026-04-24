package Text::Treesitter::Bash::Security::Rule::SensitiveAccess;
# ABSTRACT: Detect access to sensitive files and directories

use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

my @SENSITIVE_PATTERNS = (
  [ qr{/etc/shadow},       'high',   'Shadow password file access' ],
  [ qr{/etc/sudoers},      'high',   'sudoers file access' ],
  [ qr{/\.ssh/},           'high',   'SSH directory access' ],
  [ qr{/\.aws/},           'high',   'AWS credentials directory access' ],
  [ qr{/\.kube/},          'high',   'Kubernetes config access' ],
  [ qr{/etc/passwd},       'medium', 'Password database access' ],
  [ qr{/etc/group},        'medium', 'Group database access' ],
  [ qr{/proc/self/},       'medium', 'Process self introspection' ],
  [ qr{/sys/fs/},          'medium', 'Filesystem sysfs access' ],
  [ qr{/dev/},             'low',    'Device file access' ],
);

sub check {
  my ( $class, $command ) = @_;

  for my $arg ( @{ $command->{argv} // [] } ) {
    next if ref $arg;

    for my $tuple (@SENSITIVE_PATTERNS) {
      my ( $pattern, $severity, $message ) = @$tuple;

      if ( $arg =~ $pattern ) {
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