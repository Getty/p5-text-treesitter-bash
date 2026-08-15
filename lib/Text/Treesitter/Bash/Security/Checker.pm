package Text::Treesitter::Bash::Security::Checker;
# ABSTRACT: Run security rules against parsed Bash commands
our $VERSION = '0.004';
use strict;
use warnings;
use Carp qw( croak );
use Module::Load qw( load );
use Text::Treesitter::Bash;

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Checker - run security rules against parsed Bash commands

=head1 SYNOPSIS

    use Text::Treesitter::Bash::Security::Checker;

    my $checker = Text::Treesitter::Bash::Security::Checker->new(
        rules => [
            qw( PathTraversal DangerousFlags SensitiveAccess
                EnvDangerousVars UnquotedExpansion MissingAbsolutePath ),
        ],
    );

    my @issues = $checker->check_source( $bash_source );

    for my $i (@issues) {
        printf "[%s] %s: %s\n",
            $i->{severity}, $i->{rule}, $i->{message};
    }

=head1 DESCRIPTION

This is the dispatcher that wires a list of
L<Text::Treesitter::Bash::Security::Rule> classes (or instances) and
runs them over each parsed command. Two entry points:

=over 4

=item C<check_commands(@commands)> - takes already-walked command
hashrefs (see L<Text::Treesitter::Bash/commands>).

=item C<check_source($source)> - parses the source first, then runs
the rules. Convenience wrapper.

=back

Each rule's C<check> method is called once per command. The checker
collects every returned issue into a flat list (rules may return zero,
one, or many issues per command).

=head1 METHODS

=head2 new

    my $checker = Text::Treesitter::Bash::Security::Checker->new(
        rules => \@rule_specs,
    );

C<@rule_specs> is a list of either bare class-name suffixes (resolved
to C<Text::Treesitter::Bash::Security::Rule::$name> and loaded via
L<Module::Load>) or already-loaded class names or blessed rule
instances. The order is preserved and is the order in which rules run
per command.

=head2 check_commands

    my @issues = $checker->check_commands( @command_hashrefs );

Runs every rule against each command and returns a flat array of
issue hashrefs. Each issue has at least:

    {
        rule     => 'DangerousFlags',
        severity => 'low' | 'medium' | 'high',
        message  => 'Human-readable explanation',
        # optional context fields depending on the rule:
        command  => 'rm',
        arg      => '-rf',
        source   => 'rm -rf /tmp/x',
        ...
    }

Returns an empty list if nothing matched.

=head2 check_source

    my @issues = $checker->check_source( $bash_source );

Parses C<$bash_source> via L<Text::Treesitter::Bash> and delegates to
C<check_commands>. Equivalent to:

    my @cmds = Text::Treesitter::Bash->new->commands($source);
    my @issues = $checker->check_commands(@cmds);

=head1 SHIPPED RULES

=over 4

=item L<Text::Treesitter::Bash::Security::Rule::PathTraversal>

Detects C<../>, C</etc/../>, C</proc/../>, C</sys/../> in argv,
plus sensitive introspective paths like C</proc/self/>, C</proc/$$/>,
C</sys/fs>.

=item L<Text::Treesitter::Bash::Security::Rule::DangerousFlags>

Detects C<rm -rf>, C<rm --force --recursive>, and similar
high-blast-radius flag combinations.

=item L<Text::Treesitter::Bash::Security::Rule::SensitiveAccess>

Detects argv that touches C</etc/shadow>, C</etc/sudoers>,
C<~/.ssh/>, C<~/.aws/>, C<~/.kube/>, C<~/.docker/config.json>,
C<~/.gnupg/private-keys>, C<~/.git-credentials>, C<~/.netrc>,
C<~/.pypirc>, C<~/.npmrc>, C<~/.cargo/credentials>, gcloud / Azure / gh
configs, C</etc/passwd>, C</proc/self/>, C</sys/fs/>, C</dev/>.

=item L<Text::Treesitter::Bash::Security::Rule::EnvDangerousVars>

Detects setting or using C<LD_PRELOAD>, C<LD_AUDIT>,
C<DYLD_INSERT_LIBRARIES>, C<DYLD_LIBRARY_PATH>, C<BASH_ENV>,
C<ENV>, C<CDPATH>, C<GIT_DIR>.

=item L<Text::Treesitter::Bash::Security::Rule::UnquotedExpansion>

Detects unquoted C<$VAR> expansions that could word-split
(especially in path contexts).

=item L<Text::Treesitter::Bash::Security::Rule::MissingAbsolutePath>

Flags commands invoked without an absolute path, not in the common-binary
allowlist, and not a shell builtin.

=item L<Text::Treesitter::Bash::Security::Rule::DangerousExpansion>

Detects C<${!var}>, C<${var@P}>, C<${var=value}>, nested C<$()> in
C<${}> (CVE-2026-29783 class).

=item L<Text::Treesitter::Bash::Security::Rule::ReverseShellSink>

Detects classic reverse-shell constructions: C<nc -e>, C<socat exec:>,
C<bash -i> with C</dev/tcp>, C<ssh ProxyCommand>, C<mkfifo>.

=item L<Text::Treesitter::Bash::Security::Rule::DangerousFilesystem>

Detects C<dd of=/dev/sdX>, C<mkfs>, C<fdisk>, C<parted>, C<: > /etc/...>,
C<truncate -s 0> of system paths, C<shred>, mount/loop/crypto manipulation.

=item L<Text::Treesitter::Bash::Security::Rule::IFSManipulation>

Detects C<IFS=> assignments and C<$IFS>-bound expansions.

=item L<Text::Treesitter::Bash::Security::Rule::InsecureDownload>

Detects C<curl>/C<wget>/C<fetch> invocations with TLS verification
disabled (C<-k>, C<--insecure>, C<--no-check-certificate>,
C<--no-cert-check>) — C<high> — or with plaintext C<http://> URLs —
C<medium>. A second-pass scan of the full source catches URLs that
argv splitting obscured (e.g. inside a C<--data-urlencode> value).

=item L<Text::Treesitter::Bash::Security::Rule::NetworkListener>

Detects inbound listeners: C<nc -l...>, C<ncat -l>, C<socat TCP-LISTEN>,
C<ssh -R> / C<ssh -D> tunnels and SOCKS proxies (C<high>); one-liner web
servers C<python -m http.server>, C<php -S>, C<ruby -run -e httpd>,
C<npx http-server> (C<medium>; C<high> when bound to C<0.0.0.0>, C<low>
when bound to localhost).

=item L<Text::Treesitter::Bash::Security::Rule::ForkBomb>

Detects the textbook fork-bomb pattern: a function whose body
recurses into itself with a pipe or background operator
(C<high>). C<bash -c '...'> wrappers are out of scope here — they
should be caught by C<dynamic_shell> / C<shell_interpreter>.

=back

=head1 WRITING YOUR OWN RULE

See L<Text::Treesitter::Bash::Security::Rule> for the contract.
Each rule is a class with a C<check($command)> method returning
zero, one, or many issue hashrefs.

=head1 SEE ALSO

L<Text::Treesitter::Bash>, L<Text::Treesitter::Bash::Security::Rule>.

=cut

sub new {
  my ( $class, %args ) = @_;

  my @rules = @{ $args{rules} // [] };
  my @instances;

  for my $rule (@rules) {
    if ( !ref $rule ) {
      my $class_name = "Text::Treesitter::Bash::Security::Rule::$rule";
      load($class_name);
      croak "Rule class '$class_name' does not implement check()"
        unless $class_name->can('check');
      $rule = $class_name;
    }
    elsif ( ref $rule eq 'SCALAR' || ref $rule eq '' ) {
      croak "Rule specification must be a class name or blessed object, got scalar";
    }
    elsif ( !$rule->can('check') ) {
      croak "Rule '$rule' does not implement check()";
    }
    push @instances, $rule;
  }

  return bless { rules => \@instances }, $class;
}

sub check_commands {
  my ( $self, @commands ) = @_;

  my @issues;

  for my $command (@commands) {
    for my $rule ( @{ $self->{rules} } ) {
      my @result = $rule->check($command);
      # Defensive: filter out anything that isn't a hashref, so a rule
      # that mistakenly returns `undef` (single scalar) does not corrupt
      # the issue list. The recommended contract is `()` for no-match;
      # see L<Text::Treesitter::Bash::Security::Rule/CONTRACT>.
      push @issues, grep { ref eq 'HASH' } @result;
    }
  }

  return @issues;
}

sub check_source {
  my ( $self, $source ) = @_;

  my $bash = Text::Treesitter::Bash->new;
  my @commands = $bash->commands($source);

  return $self->check_commands(@commands);
}

1;