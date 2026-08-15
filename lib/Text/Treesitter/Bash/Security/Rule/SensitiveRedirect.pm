package Text::Treesitter::Bash::Security::Rule::SensitiveRedirect;
# ABSTRACT: Detect redirections to sensitive file paths or block devices
our $VERSION = '0.001';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::SensitiveRedirect - detect shell redirects into sensitive paths

=head1 DESCRIPTION

Walks the C<redirects> field of each command (produced by
L<Text::Treesitter::Bash/commands>) and flags any redirect whose target
or operator matches a sensitive destination:

=over 4

=item high - C<E<gt>E<gt> /etc/shadow>, C<E<gt> /etc/passwd>, C<E<gt> /etc/sudoers>, C<E<gt> /dev/sd*>, C<E<gt> /dev/nvme*>, C<E<gt> /dev/vd*>, C<E<gt> ~/.ssh/>, C<E<gt> ~/.aws/>, C<E<gt> ~/.kube/>, C<E<gt> ~/.gnupg/>

=item medium - C<E<gt> /etc/>, C<E<gt> /dev/null>, C<E<gt> ~/.bash_history>, C<E<gt> /var/log/>

=back

Input redirects (C<E<lt>) and duplicates (C<E<gt>E<amp>1>) are matched
by target on the same way.

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>,
L<Text::Treesitter::Bash::Security::Rule::SensitiveAccess>,
L<Text::Treesitter::Bash::Security::Rule::PathTraversal>.

=cut

# Severity-ordered list. Patterns are anchored to a complete path
# segment so '/etc/passwd' doesn't match '/etc/passwd_backup'.
my @SENSITIVE_REDIRECTS = (
  # high — direct credential stores being overwritten
  [ qr{/(?:etc/(?:shadow|shadow-|sudoers|sudoers\.d/)|etc/(?:gshadow|gshadow-))\b}, 'high',
    'Redirect into credential store' ],
  [ qr{/(?:etc/(?:passwd|group)\b)(?![\w/])}, 'high',
    'Redirect into system account database' ],
  # high — block-device writes
  [ qr{/dev/(?:sd[a-z]|nvme\d+n\d+|vd[a-z]|mmcblk\d+|xvd[a-z])(?:\b|/|$)}, 'high',
    'Redirect into block device' ],
  # high — credential directory writes
  [ qr{/(?:\.ssh|\.aws|\.kube|\.gnupg)/}, 'high',
    'Redirect into credential directory' ],
  # medium — system config / log / history
  [ qr{/(?:etc/|\.bash_history|\.bash_profile|\.profile|\.zshrc|\.zsh_history)\b}, 'medium',
    'Redirect into user config or system config' ],
  [ qr{/(?:var/log/|var/run/|\.docker/|\.config/)\b}, 'medium',
    'Redirect into process / config directory' ],
  [ qr{/dev/(?:null|zero|full|tty|stdin|stdout|stderr|random|urandom)\b}, 'low',
    'Redirect into standard device file' ],
);

sub check {
  my ( $class, $command ) = @_;

  my @issues;
  my $redirects = $command->{redirects} // [];

  for my $r (@$redirects) {
    my $operator = $r->{operator} // '';
    my $target   = $r->{target}   // '';

    # Only check output-side redirects and input-side file redirects.
    # Duplicates (>&1, 2>&1) point at FDs, not files — skip those.
    next if $operator =~ m/&/;

    for my $tuple (@SENSITIVE_REDIRECTS) {
      my ( $pattern, $severity, $message ) = @$tuple;
      next unless $target =~ $pattern;
      push @issues, {
        rule     => 'SensitiveRedirect',
        severity => $severity,
        message  => "$message: $operator $target",
        operator => $operator,
        target   => $target,
        command  => $command->{command},
      };
    }
  }

  return @issues;
}

1;
