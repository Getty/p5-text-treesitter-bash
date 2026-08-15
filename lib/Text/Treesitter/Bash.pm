package Text::Treesitter::Bash;
# ABSTRACT: Parse Bash with Text::Treesitter and extract executable commands
our $VERSION = '0.003';
use strict;
use warnings;
use Alien::Tree::Sitter ();
use Carp qw( croak );
use File::ShareDir qw( dist_dir );
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Text::Treesitter;
use Text::Treesitter::Language;

=encoding utf8

=head1 NAME

Text::Treesitter::Bash - Parse Bash with Text::Treesitter and extract executable commands

=head1 SYNOPSIS

    use Text::Treesitter::Bash;

    my $bash = Text::Treesitter::Bash->new;
    my $tree = $bash->parse( $source );

    my @commands = $bash->commands( $source );
    for my $cmd (@commands) {
        printf "%s [%s] argv=(%s)\n",
            $cmd->{command}, $cmd->{start_byte},
            join( ',', @{ $cmd->{argv} } );
    }

    my @findings = $bash->findings( $source );
    for my $f (@findings) {
        print "$f->{type}: $f->{message}\n";
    }

=head1 DESCRIPTION

Text::Treesitter::Bash vendors the upstream L<tree-sitter-bash|https://github.com/tree-sitter/tree-sitter-bash>
grammar (currently 0.20.5) and exposes a small Perl layer on top of L<Text::Treesitter>:

=over 4

=item * C<parse> - returns the raw tree-sitter tree.

=item * C<commands> - walks the tree and returns one hash per C<command>,
C<declaration_command>, C<unset_command> or C<test_command> AST node,
including argv, source span, the enclosing shell context (pipeline,
subshell, negated, ...) and the surrounding operators (C<&&>, C<||>,
C<|>, C<|&>, C<;>, newline).

=item * C<findings> - convenience policy-light checks built on top of
C<commands>: shell-interpreters, dynamic-evaluation flags
(C<bash -c>, C<perl -e>, ...), C<eval>/C<source>/C<.>, and
network-fetch piped into shell.

=back

For richer security rules, see L<Text::Treesitter::Bash::Security::Checker>.

=head1 METHODS

=head2 new

    my $bash = Text::Treesitter::Bash->new;
    my $custom = Text::Treesitter::Bash->new( lang_dir => '/opt/ts-bash' );

Returns a parser instance. The optional C<lang_dir> points to a directory
containing the tree-sitter grammar sources (C<src/parser.c>, C<src/scanner.c>,
C<src/node-types.json>, C<package.json>); defaults to the grammar shipped in
this distribution's share dir.

=head2 parse

    my $tree = $bash->parse( $source );

Parses C<$source> and returns a L<Text::Treesitter::Tree>. Croaks if C<$source>
is undef.

=head2 commands

    my @commands = $bash->commands( $source );

Returns a list of command hashrefs. Each command has:

=over 4

=item source

Raw text of the AST node (operator + whitespace preserved).

=item command

First word of the command, basename-stripped, quotes stripped
(C<'foo'>, C<"foo"> both become C<foo>).

=item argv

Arrayref of all args, including C<command> as C<argv[0]>. Raw, with
quotes and expansions intact.

=item start_byte, end_byte

Byte offsets into the original source.

=item context

Arrayref of enclosing node types. E.g. C<['pipeline']> for commands
inside C<foo | bar>, C<['command_substitution']> for commands inside
C<$(...)> or backticks.

=item before_op, after_op

The shell operator (C<&&>, C<||>, C<|>, C<|&>, C<;>, newline) that
appears before / after this command in source order. Either may be
undef at the start/end of the input.

=back

=head2 findings

    my @findings = $bash->findings( $source );

Runs a fixed set of policy-light checks and returns a list of hashrefs
with C<type> and C<message> (and the offending command). Recognised
C<type> values:

=over 4

=item shell_interpreter

C<sh>, C<bash>, C<dash>, C<zsh>, C<fish>, C<ksh> invoked directly.
Often a sign that the caller wants to run arbitrary string.

=item dynamic_shell

C<bash -c ...>, C<perl -e ...>, C<ruby -e ...>, C<python -c ...>,
C<node -e ...>. Code passed as a string is opaque to the caller.

=item shell_eval

C<eval>, C<source>, C<.> (dot/source) used. Reads and executes a
file in the current shell.

=item network_to_shell

A network fetcher (C<curl>, C<wget>, C<fetch>, C<aria2c>) piped into
a shell interpreter. Classic "curl|sh" install vector.

=back

For richer rules see L<Text::Treesitter::Bash::Security::Checker>.

=head1 TREE-SITTER NOTES

This distribution vendors the grammar in F<share/tree-sitter-bash/>. On
first use, sources are copied into a C<File::Temp> directory and compiled
via L<Text::Treesitter::Language::build>. Compilation is silent unless
it fails; the resulting C<.so> lives in TMPDIR until CLEANUP.

=head1 SEE ALSO

L<Text::Treesitter>, L<Text::Treesitter::Bash::Security::Checker>,
L<Text::Treesitter::Bash::Security::Rule>,
L<https://github.com/tree-sitter/tree-sitter-bash>.

=cut

sub new {
  my ( $class, %args ) = @_;

  return bless {
    lang_dir => $args{lang_dir},
    _tmpdir  => undef,
    _ts      => undef
  }, $class;
}

sub parse {
  my ( $self, $source ) = @_;
  croak 'Source required' unless defined $source;
  return $self->_treesitter->parse_string($source);
}

sub commands {
  my ( $self, $source ) = @_;

  my $tree = $self->parse($source);
  my @commands;
  $self->_walk_node( $tree->root_node, [], \@commands, undef );
  return @commands;
}

sub findings {
  my ( $self, $source ) = @_;

  my @commands = $self->commands($source);
  my @findings;

  for my $command (@commands) {
    my $name = _command_basename( $command->{command} );

    if ( _is_shell_interpreter($name) ) {
      push @findings, {
        type    => 'shell_interpreter',
        message => "shell interpreter '$command->{command}' is executed",
        command => $command
      };
    }

    if ( _is_dynamic_shell( $name, $command->{argv} ) ) {
      push @findings, {
        type    => 'dynamic_shell',
        message => "dynamic code flag used with '$command->{command}'",
        command => $command
      };
    }

    if ( $name eq 'eval' || $name eq 'source' || $name eq '.' ) {
      push @findings, {
        type    => 'shell_eval',
        message => "shell evaluation command '$command->{command}' is executed",
        command => $command
      };
    }
  }

  for my $index ( 1 .. $#commands ) {
    my $left  = $commands[ $index - 1 ];
    my $right = $commands[$index];

    next unless ( $left->{after_op} // '' ) =~ m/^\|/;
    next unless ( $right->{before_op} // '' ) =~ m/^\|/;
    next unless _is_network_fetcher( _command_basename( $left->{command} ) );
    next unless _is_shell_interpreter( _command_basename( $right->{command} ) );

    push @findings, {
      type     => 'network_to_shell',
      message  => "network command '$left->{command}' pipes into shell '$right->{command}'",
      commands => [ $left, $right ]
    };
  }

  return @findings;
}

sub _treesitter {
  my ( $self ) = @_;

  return $self->{_ts} if $self->{_ts};

  my $lang_dir = $self->{lang_dir} // $self->_build_runtime_lang_dir;
  my $lang_lib = path($lang_dir)->child('tree-sitter-bash.so');

  if ( !-f $lang_lib ) {
    my $stdout = q{};
    open my $capture, '>', \$stdout or croak "Unable to capture build output: $!";
    local *STDOUT = $capture;
    Text::Treesitter::Language::build( "$lang_lib", "$lang_dir" );
  }

  return $self->{_ts} = Text::Treesitter->new(
    lang_name => 'bash',
    lang_dir  => "$lang_dir",
    lang_lib  => "$lang_lib"
  );
}

sub _build_runtime_lang_dir {
  my ( $self ) = @_;

  my $share = $self->_find_share_dir->child('tree-sitter-bash');
  my $tmp   = path( tempdir( 'text-treesitter-bash-XXXXXX', TMPDIR => 1, CLEANUP => 1 ) );

  for my $file (
    qw(
      LICENSE
      package.json
      src/parser.c
      src/scanner.c
      src/node-types.json
    )
  ) {
    my $source = $share->child( split m{/}, $file );
    my $target = $tmp->child( split m{/}, $file );

    next unless -f $source;

    $target->parent->mkpath;
    $source->copy($target);
  }

  # tree-sitter-bash's src/parser.c does `#include "tree_sitter/parser.h"`.
  # Text::Treesitter::Language::build has no -I hook, so we copy the
  # canonical header (from Alien::Tree::Sitter's vendored tree-sitter)
  # next to src/ so the include resolves locally.
  my ($inc) = Alien::Tree::Sitter->cflags =~ m/-I(\S+)/;
  if ($inc && -d "$inc/tree_sitter") {
    my $target = $tmp->child('src')->child('tree_sitter');
    $target->mkpath;
    for my $header (path("$inc/tree_sitter")->children) {
      $header->copy( $target->child( $header->basename ) );
    }
  }

  $self->{_tmpdir} = $tmp;
  return $tmp;
}

sub _find_share_dir {
  my ( $self ) = @_;

  my $installed = eval { path( dist_dir('Text-Treesitter-Bash') ) };
  return $installed if $installed && -d $installed;

  my $module_path = $INC{'Text/Treesitter/Bash.pm'};
  if ($module_path) {
    my $share = path($module_path)->parent(4)->child('share');
    return $share if -d $share;
  }

  croak 'Could not find Text-Treesitter-Bash share directory';
}

sub _walk_node {
  my ( $self, $node, $context, $commands, $before_op ) = @_;

  my $type = $node->type;

  if ( $type eq 'command' ) {
    push @$commands, $self->_command_entry( $node, $context, $before_op );
    $self->_walk_command_children( $node, $context, $commands );
    return;
  }

  if ( $type eq 'declaration_command' || $type eq 'unset_command' || $type eq 'test_command' ) {
    push @$commands, $self->_simple_command_entry( $node, $context, $before_op );
    $self->_walk_command_children( $node, $context, $commands );
    return;
  }

  if ( $type eq 'command_substitution' || $type eq 'process_substitution' || $type eq 'subshell' ) {
    $self->_walk_children( $node, [ @$context, $type ], $commands, undef );
    return;
  }

  if ( $type eq 'pipeline' ) {
    $self->_walk_children( $node, [ @$context, 'pipeline' ], $commands, $before_op );
    return;
  }

  if ( $type eq 'negated_command' ) {
    $self->_walk_children( $node, [ @$context, 'negated' ], $commands, $before_op );
    return;
  }

  if ( $type eq 'redirected_statement' ) {
    my $body = $node->try_child_by_field_name('body');
    if ($body) {
      $self->_walk_node( $body, $context, $commands, $before_op );
      return;
    }
  }

  $self->_walk_children( $node, $context, $commands, $before_op );
}

sub _walk_children {
  my ( $self, $node, $context, $commands, $initial_before_op ) = @_;

  my $pending_op = $initial_before_op;

  for my $child ( $node->child_nodes ) {
    if ( !$child->is_named ) {
      my $operator = _operator_text( $child->text );
      if ( defined $operator ) {
        $commands->[-1]{after_op} = $operator if @$commands;
        $pending_op = $operator;
      }
      next;
    }

    my $before_count = @$commands;
    $self->_walk_node( $child, $context, $commands, $pending_op );
    $pending_op = undef if @$commands > $before_count;
  }
}

sub _walk_command_children {
  my ( $self, $node, $context, $commands ) = @_;

  for my $child ( $node->child_nodes ) {
    next if !$child->is_named;
    next if $child->type eq 'command_name';
    $self->_walk_node( $child, $context, $commands, undef );
  }
}

sub _command_entry {
  my ( $self, $node, $context, $before_op ) = @_;

  my ( $name, @args );
  my $seen_name = 0;
  my @fields = $node->field_names_with_child_nodes;

  while (@fields) {
    my $field = shift @fields;
    my $child = shift @fields;

    if ( defined $field && $field eq 'name' ) {
      $name = _clean_word( $child->text );
      $seen_name = 1;
    }
    elsif ( defined $field && $field eq 'argument' ) {
      push @args, $child->text;
    }
    elsif ( !defined $field && $seen_name && _is_argument_node($child) ) {
      push @args, $child->text;
    }
  }

  $name //= _clean_word( _first_child_text($node) );

  return {
    source     => $node->text,
    command    => $name,
    argv       => [ $name, @args ],
    start_byte => $node->start_byte,
    end_byte   => $node->end_byte,
    context    => [@$context],
    before_op  => $before_op,
    after_op   => undef
  };
}

sub _simple_command_entry {
  my ( $self, $node, $context, $before_op ) = @_;

  my $source = $node->text;
  my @argv = grep { length $_ } split m/\s+/, $source;
  my $name = _clean_word( $argv[0] // _first_child_text($node) );

  return {
    source     => $source,
    command    => $name,
    argv       => \@argv,
    start_byte => $node->start_byte,
    end_byte   => $node->end_byte,
    context    => [@$context],
    before_op  => $before_op,
    after_op   => undef
  };
}

sub _first_child_text {
  my ( $node ) = @_;

  for my $child ( $node->child_nodes ) {
    next if $child->is_extra;
    return $child->text;
  }

  return $node->text;
}

sub _operator_text {
  my ( $text ) = @_;

  return $text if $text eq '&&';
  return $text if $text eq '||';
  return $text if $text eq '|';
  return $text if $text eq '|&';
  return $text if $text eq ';';
  return $text if $text eq '&';
  return ';' if $text =~ m/^\s*\n\s*$/;

  return undef;
}

sub _is_argument_node {
  my ( $node ) = @_;

  return !!{
    word                 => 1,
    raw_string           => 1,
    string               => 1,
    ansi_c_string        => 1,
    translated_string    => 1,
    concatenation        => 1,
    command_substitution => 1,
    expansion            => 1,
    simple_expansion     => 1,
    arithmetic_expansion => 1,
    array                => 1,
    subscript            => 1,
    regex                => 1,
    extglob_pattern      => 1,
    brace_expression     => 1,
  }->{ $node->type };
}

sub _clean_word {
  my ( $word ) = @_;

  return q{} unless defined $word;
  $word =~ s/^\s+//;
  $word =~ s/\s+$//;

  if ( $word =~ m/\A'([^']*)'\z/ || $word =~ m/\A"([^"]*)"\z/ ) {
    return $1;
  }

  return $word;
}

sub _command_basename {
  my ( $command ) = @_;

  $command = _clean_word($command);
  $command =~ s{\A.*/}{};
  return $command;
}

sub _is_shell_interpreter {
  my ( $name ) = @_;

  return !!{
    sh   => 1,
    bash => 1,
    dash => 1,
    zsh  => 1,
    fish => 1,
    ksh  => 1
  }->{$name};
}

sub _is_network_fetcher {
  my ( $name ) = @_;

  return !!{
    curl   => 1,
    wget   => 1,
    fetch  => 1,
    aria2c => 1
  }->{$name};
}

sub _is_dynamic_shell {
  my ( $name, $argv ) = @_;

  return 0 if !@$argv;

  if ( _is_shell_interpreter($name) ) {
    return scalar grep { $_ eq '-c' } @$argv;
  }

  if ( $name eq 'perl' || $name eq 'ruby' || $name eq 'node' ) {
    return scalar grep { $_ eq '-e' } @$argv;
  }

  if ( $name =~ m/\Apython(?:\d+(?:\.\d+)?)?\z/ ) {
    return scalar grep { $_ eq '-c' } @$argv;
  }

  return 0;
}

1;
