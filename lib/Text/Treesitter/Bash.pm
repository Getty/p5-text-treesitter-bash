package Text::Treesitter::Bash;
# ABSTRACT: Parse Bash with Text::Treesitter and extract executable commands
our $VERSION = '0.008';
use strict;
use warnings;
use Alien::Tree::Sitter ();
use Carp qw( croak );
use Encode qw();
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
undef at the start/end of the input. B<Note:> C<&> (background) is not
emitted as C<after_op> — it is a background marker, not a sequence
operator.

=item redirects

Arrayref of redirect nodes attached to the command. Each entry is a
hashref with C<type> (C<file_redirect>, C<herestring_redirect>,
C<heredoc_redirect>), C<operator> (e.g. C<< >= >>, C<< 2>& >>,
C<< <<< >>), C<target> (the destination word for file_redirect /
herestring, or the heredoc start marker for heredoc), and C<text>
(the full raw text of the redirect). Empty array if no redirects.

=item negated

Boolean. Set to C<1> when the command sits inside a C<negated_command>
node (i.e. after the C<!> operator). Absent otherwise. Security rules
that want to know whether a command's exit status was discarded can
match on this rather than the C<'negated'> context string.

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
  # tree-sitter is byte-oriented; feeding it invalid UTF-8 (or a NUL
  # byte, which bash grammars generally reject) results in opaque
  # runtime errors. Reject up front so callers get a clear message.
  my $copy = $source;
  my $decoded = eval { Encode::decode( 'UTF-8', $copy, Encode::FB_CROAK ); 1 };
  croak "Source contains invalid UTF-8: $@" unless $decoded;
  if ( index( $source, "\0" ) >= 0 ) {
    croak 'Source contains a NUL byte';
  }
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

  return @findings if !@commands;

  for my $index ( 1 .. $#commands ) {
    my $left  = $commands[ $index - 1 ];
    my $right = $commands[$index];

    # `^\|` would also match `||` (OR), which is not a pipe. Anchor the
    # alternation explicitly to `|` and `|&` only.
    next unless ( $left->{after_op} // '' ) =~ m/^\|(?:&)?\z/;
    next unless ( $right->{before_op} // '' ) =~ m/^\|(?:&)?\z/;
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
    # If the build silently failed (missing gcc, missing tree-sitter
    # headers, etc.), Text::Treesitter::Language::build returns without
    # producing the .so. Surface the captured compiler output rather
    # than letting the loader fail with a confusing FileNotFound.
    if ( !-f $lang_lib ) {
      croak "Failed to build tree-sitter-bash grammar at $lang_lib: $stdout";
    }
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
  my ( $self, $node, $context, $commands, $before_op, $negated ) = @_;

  my $type = $node->type;

  if ( $type eq 'command' ) {
    push @$commands, $self->_command_entry( $node, $context, $before_op, $negated );
    $self->_walk_command_children( $node, $context, $commands, $negated );
    return;
  }

  if ( $type eq 'declaration_command' || $type eq 'unset_command' || $type eq 'test_command' ) {
    my $entry = $self->_simple_command_entry( $node, $context, $before_op, $negated );
    # `test_command` (`[[ ... ]]`, `[ ... ]`) is a condition, not an
    # executed command — tag it so security rules can skip it.
    $entry->{test}    = 1 if $type eq 'test_command';
    $entry->{context} = [ 'test', @{ $entry->{context} } ] if $type eq 'test_command';
    push @$commands, $entry;
    # The children of these node types are not commands themselves
    # (variable_assignment, variable_name, [[ ... ]], etc.) — recursing
    # would produce duplicate entries.
    return;
  }

  if ( $type eq 'variable_assignment' ) {
    push @$commands, {
      source     => $node->text,
      command    => $node->text,
      argv       => [ $node->text ],
      start_byte => $node->start_byte,
      end_byte   => $node->end_byte,
      context    => [@$context],
      before_op  => $before_op,
      after_op   => undef,
      ( $negated ? ( negated => 1 ) : () ),
    };
    return;
  }

  if ( $type eq 'command_substitution' || $type eq 'process_substitution' || $type eq 'subshell' ) {
    # The wrapper itself sits behind the surrounding `before_op` (e.g.
    # `cmd1 && (cmd2; cmd3)` — cmd2 is behind `&&`). Propagate the
    # pending operator into the wrapper so the inner command's
    # `before_op` reflects the surrounding flow.
    $self->_walk_children( $node, [ @$context, $type ], $commands, $before_op, $negated );
    return;
  }

  if ( $type eq 'pipeline' ) {
    $self->_walk_children( $node, [ @$context, 'pipeline' ], $commands, $before_op, $negated );
    return;
  }

  if ( $type eq 'negated_command' ) {
    # Mark every inner command as negated so security rules can match
    # on the boolean rather than the context string.
    $self->_walk_children( $node, [ @$context, 'negated' ], $commands, $before_op, 1 );
    return;
  }

  # Control-flow wrappers: push their kind into the context so rules
  # can scope findings to the right scope (e.g. a `rm` inside an `if`
  # body is conditional, but a `rm` in a `for` loop iterates over many
  # inputs and warrants a higher severity).
  if ( $type eq 'if_statement'
    || $type eq 'for_statement'
    || $type eq 'while_statement'
    || $type eq 'case_statement'
    || $type eq 'elif_clause'
    || $type eq 'else_clause'
    || $type eq 'do_group' )
  {
    $self->_walk_children( $node, [ @$context, $type ], $commands, $before_op, $negated );
    return;
  }

  # `function_definition` introduces a named function (the `word`
  # child). We extract that name as a separate command-like entry
  # so callers can see function declarations, then walk the body with
  # `function_definition` in the context.
  if ( $type eq 'function_definition' ) {
    my $name;
    for my $child ( $node->child_nodes ) {
      if ( $child->is_named && $child->type eq 'word' ) {
        $name = _clean_word( $child->text );
        last;
      }
    }
    if ( defined $name ) {
      push @$commands, {
        source     => $node->text,
        command    => $name,
        argv       => [ $name ],
        start_byte => $node->start_byte,
        end_byte   => $node->end_byte,
        context    => [ 'function_definition', @$context ],
        before_op  => $before_op,
        after_op   => undef,
        function   => 1,
        ( $negated ? ( negated => 1 ) : () ),
      };
    }
    $self->_walk_children( $node, [ @$context, 'function_definition' ], $commands, $before_op, $negated );
    return;
  }

  if ( $type eq 'redirected_statement' ) {
    my $body = $node->try_child_by_field_name('body');
    if ($body) {
      my $before = @$commands;
      $self->_walk_node( $body, $context, $commands, $before_op, $negated );
      # Promote the source to include the redirect text so security rules
      # see the full statement (e.g. ": > /etc/passwd" or
      # "bash -i >& /dev/tcp/..."). Also collect any redirect targets
      # so rules can match on file paths / destinations.
      if (@$commands > $before) {
        $commands->[-1]{source} = $node->text;
        for my $child ( $node->child_nodes ) {
          $self->_collect_redirects( $child, $commands->[-1] );
        }
      }
      return;
    }
  }

  $self->_walk_children( $node, $context, $commands, $before_op, $negated );
}

sub _walk_children {
  my ( $self, $node, $context, $commands, $initial_before_op, $negated ) = @_;

  my $pending_op = $initial_before_op;
  my $last_was_command = 0;

  for my $child ( $node->child_nodes ) {
    if ( !$child->is_named ) {
      my $operator = _operator_text( $child->text );
      if ( defined $operator ) {
        # & is a background marker, not a sequence operator — don't record
        # it as after_op. The next command, if any, still sees it as
        # before_op via $pending_op.
        $commands->[-1]{after_op} = $operator
          if $operator ne '&' && @$commands;
        $pending_op = $operator;
        $last_was_command = 0;
      }
      next;
    }

    # tree-sitter-bash does not emit an operator between sibling commands
    # at the same level (including the implicit newline case). When the
    # previous sibling was a command and no operator was seen, treat the
    # gap as an implicit `;` and propagate it as the pending before_op.
    if ( $last_was_command && !defined $pending_op && @$commands ) {
      if ( !defined $commands->[-1]{after_op} ) {
        $commands->[-1]{after_op} = ';';
      }
      $pending_op = ';';
    }

    my $before_count = @$commands;
    $self->_walk_node( $child, $context, $commands, $pending_op, $negated );
    $pending_op = undef;
    $last_was_command = @$commands > $before_count
      ? ( $child->type eq 'command' ? 1 : 0 )
      : 0;
  }
}

sub _walk_command_children {
  my ( $self, $node, $context, $commands, $negated ) = @_;

  for my $child ( $node->child_nodes ) {
    next if !$child->is_named;
    next if $child->type eq 'command_name';
    # Prefix assignments (e.g. `LD_PRELOAD=x command`) are not separate
    # commands — they belong to the containing command. Their text is
    # already visible via the parent's source raw bytes.
    next if $child->type eq 'variable_assignment';

    if (   $child->type eq 'file_redirect'
      || $child->type eq 'herestring_redirect'
      || $child->type eq 'heredoc_redirect' )
    {
      $self->_collect_redirects( $child, $commands->[-1] ) if @$commands;
      next;
    }

    $self->_walk_node( $child, $context, $commands, undef, $negated );
  }
}

# Extract structured redirect information from a file_redirect,
# herestring_redirect, or heredoc_redirect node and append each entry to
# the command hash's `redirects` array.
sub _collect_redirects {
  my ( $self, $node, $command ) = @_;

  my $type = $node->type;
  my $text = $node->text;
  $command->{redirects} //= [];

  return unless $type eq 'file_redirect'
            || $type eq 'herestring_redirect'
            || $type eq 'heredoc_redirect';

  # Iterate through the redirect's children. The redirection symbol (e.g.
  # `>`, `>>`, `<`, `>&`, `<<<`, `<<`) is an unnamed child; the target
  # is a named child (word, number, raw_string, heredoc_start, ...).
  # An optional file_descriptor precedes the symbol.
  my $descriptor;
  my $operator;
  my $target;
  my @named;

  for my $child ( $node->child_nodes ) {
    if ( !$child->is_named ) {
      $operator = $child->text;
    }
    elsif ( $child->type eq 'file_descriptor' ) {
      $descriptor = $child->text;
    }
    else {
      push @named, $child;
    }
  }

  # For file_redirect, the target is the first named child after the
  # descriptor. For herestring, it's the first named child. For heredoc,
  # it's the heredoc_start (first named child).
  $target = $named[0]->text if @named;

  if ( defined $descriptor && defined $operator ) {
    $operator = $descriptor . $operator;
  }

  push @{ $command->{redirects} }, {
    type     => $type,
    operator => $operator,
    target   => $target,
    text     => $text,
  };
}

sub _command_entry {
  my ( $self, $node, $context, $before_op, $negated ) = @_;

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
      # process_substitution nodes are tagged as `argument` fields in
      # the bash grammar, but they are wrapper constructs (process
      # substitution creates an FD, not a string value). Skipping them
      # here leaves them to be walked by _walk_command_children, which
      # adds the inner command with the correct context. command_substitution
      # (i.e. $(...) / backticks), on the other hand, IS a real argument
      # whose value is the captured stdout of the inner command — keep it.
      next if $child->type eq 'process_substitution';
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
    after_op   => undef,
    ( $negated ? ( negated => 1 ) : () ),
  };
}

sub _simple_command_entry {
  my ( $self, $node, $context, $before_op, $negated ) = @_;

  my $source = $node->text;
  my $type   = $node->type;

  my ( $name, @argv ) = $self->_argv_from_simple_children($node);

  return {
    source     => $source,
    command    => $name,
    argv       => \@argv,
    start_byte => $node->start_byte,
    end_byte   => $node->end_byte,
    context    => [@$context],
    before_op  => $before_op,
    after_op   => undef,
    ( $negated ? ( negated => 1 ) : () ),
  };
}

# Walk the AST children of a declaration_command / unset_command /
# test_command instead of splitting the source text on whitespace.
# `export FOO="hello world"` therefore produces
# argv = ['export', 'FOO="hello world"'] rather than the broken
# ['export', 'FOO="hello', 'world"'] we used to return.
sub _argv_from_simple_children {
  my ( $self, $node ) = @_;

  my $type = $node->type;
  my ( $name, @argv );

  if ( $type eq 'declaration_command' ) {
    # First child is the unnamed keyword (export / local / declare /
    # typeset / readonly); remaining named children are option
    # `word` nodes (e.g. `declare -i`) and `variable_assignment`
    # nodes whose raw text already preserves quoting.
    for my $child ( $node->child_nodes ) {
      if ( !$child->is_named ) {
        $name = $child->text;
        push @argv, $child->text;
      }
      elsif ( $child->type eq 'variable_assignment' ) {
        push @argv, $child->text;
      }
      elsif ( $child->type eq 'word' ) {
        # option flags like `-i`, `-p`, `-x`, `-r` etc.
        push @argv, $child->text;
      }
    }
  }
  elsif ( $type eq 'unset_command' ) {
    for my $child ( $node->child_nodes ) {
      if ( !$child->is_named ) {
        $name = $child->text;
        push @argv, $child->text;
      }
      elsif ( $child->type eq 'variable_name' ) {
        push @argv, $child->text;
      }
    }
  }
  elsif ( $type eq 'test_command' ) {
    # test_command structure: [[  <expr>  ]] (or [ ... ]).
    # The leading/trailing brackets are unnamed; the middle is a
    # named expression. Push everything verbatim so callers see the
    # full predicate text.
    for my $child ( $node->child_nodes ) {
      push @argv, $child->text;
    }
    $name = $argv[0] // q{};
  }
  else {
    # Fallback: split on whitespace. Should never trigger for known
    # simple_command types.
    @argv = grep { length $_ } split m/\s+/, $node->text;
    $name = $argv[0] // _first_child_text($node);
  }

  $name //= q{};
  $name = _clean_word($name);
  return ( $name, @argv );
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
    sh      => 1,
    bash    => 1,
    dash    => 1,
    zsh     => 1,
    fish    => 1,
    ksh     => 1,
    csh     => 1,
    tcsh    => 1,
    ash     => 1,
    busybox => 1,
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

  # perl: -e, -E (with features), -p/-n (read lines), -pe/-ne (loop+exec),
  #       -i (in-place, often paired with -pe/-ne).
  if ( $name eq 'perl' ) {
    return scalar grep { m/^-[eEpni]|^-[pPnN][eE]\z/ } @$argv;
  }

  # ruby: -e evaluates a string, -r/--require loads a library (often used
  #       with require-time side effects).
  if ( $name eq 'ruby' ) {
    return scalar grep { $_ eq '-e' || $_ eq '--eval' || m/^-r/ } @$argv;
  }

  if ( $name eq 'node' ) {
    return scalar grep { $_ eq '-e' || $_ eq '--eval' || $_ eq '-p' } @$argv;
  }

  if ( _is_python_interpreter($name) ) {
    # python -c "code" and -m module (executes a module as __main__).
    return scalar grep { $_ eq '-c' || $_ eq '-m' } @$argv;
  }

  return 0;
}

# Recognise any Python-flavoured interpreter by basename (2.1.5). Matches
# python, python3, python3.11, pypy, pypy3, jython, micropython, etc.
sub _is_python_interpreter {
  my ( $name ) = @_;

  return 1 if $name eq 'python';
  return 1 if $name =~ m/\Apython\d+(?:\.\d+)*\z/;
  return 1 if $name eq 'pypy';
  return 1 if $name =~ m/\Apypy\d+(?:\.\d+)*\z/;
  return 1 if $name eq 'jython';
  return 1 if $name eq 'micropython';
  return 1 if $name eq 'nu';

  return 0;
}

1;
