package Text::Treesitter::Bash::Security::Rule;
# ABSTRACT: Base class for security rules
our $VERSION = '0.003';
use strict;
use warnings;

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule - abstract base class for security rules

=head1 SYNOPSIS

    package Text::Treesitter::Bash::Security::Rule::YourRule;
    use parent 'Text::Treesitter::Bash::Security::Rule';

    sub check {
        my ( $class, $command ) = @_;
        return unless some_condition;
        return {
            rule     => 'YourRule',
            severity => 'low' | 'medium' | 'high',
            message  => 'Human-readable explanation',
        };
    }

    1;

=head1 DESCRIPTION

Every rule is a class with a single class-method C<check> that takes
one already-walked L<Text::Treesitter::Bash/commands> hashref and
returns zero, one, or many issue hashrefs.

=head1 CONTRACT

=head2 check

    my @issues = $class->check($command);

=over 4

=item B<$command> is a hashref as documented in L<Text::Treesitter::Bash/commands>.

=item B<Return value> may be:

=over 8

=item empty list - rule did not fire.

=item single hashref - one issue.

=item list of hashrefs - several distinct issues per command (rare; usually
when one command violates multiple sub-checks of the same rule).

=back

=back

The issue hashref MUST contain at least:

    {
        rule     => 'YourRule',
        severity => 'low' | 'medium' | 'high',
        message  => 'string',
    }

Rule-specific context fields (C<command>, C<arg>, C<source>, ...)
are encouraged but not required.

=head1 SEVERITY SCALE

=over 4

=item low - style / footgun, probably harmless but a code-smell.

=item medium - real risk under common conditions (e.g. unquoted
expansion in a path that may contain spaces).

=item high - likely exploit or data loss (e.g. C<rm -rf> of a
variable, C<LD_PRELOAD>, access to C</etc/shadow>).

=back

There is intentionally no C<critical> - criticality is a policy
decision above this layer.

=head1 CAVEATS

=over 4

=item Do not croak or die from C<check>. The checker treats C<check> as
total; an exception aborts the whole audit.

=item Do not print. Return structured data only.

=item Do not inspect the tree-sitter AST directly. The walker has
already extracted the fields you need. If a field is missing, extend
C<_command_entry> in L<Text::Treesitter::Bash>.

=back

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Checker>.

=cut

sub check {
  my ( $class, $command ) = @_;
  die 'Abstract method check() must be implemented by subclass';
}

1;