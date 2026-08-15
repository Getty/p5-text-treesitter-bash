use Test2::V0;
use Text::Treesitter::Bash;

my $bash = Text::Treesitter::Bash->new;

sub command_summary {
  my ( $source ) = @_;
  return [
    map {
      +{
        command   => $_->{command},
        argv      => $_->{argv},
        before_op => $_->{before_op},
        after_op  => $_->{after_op},
        context   => $_->{context}
      }
    } $bash->commands($source)
  ];
}

# --- Operator variants --------------------------------------------------

is command_summary('a && b'),
  [
    { command => 'a', argv => ['a'], before_op => undef, after_op => '&&', context => [] },
    { command => 'b', argv => ['b'], before_op => '&&',  after_op => undef, context => [] }
  ],
  '&& operator attaches both sides';

is command_summary('a || b'),
  [
    { command => 'a', argv => ['a'], before_op => undef, after_op => '||', context => [] },
    { command => 'b', argv => ['b'], before_op => '||',  after_op => undef, context => [] }
  ],
  '|| operator attaches both sides';

is command_summary('a | b'),
  [
    { command => 'a', argv => ['a'], before_op => undef, after_op => '|', context => ['pipeline'] },
    { command => 'b', argv => ['b'], before_op => '|',  after_op => undef, context => ['pipeline'] }
  ],
  '| pipeline propagates both sides with pipeline context';

# --- Newline acts as ; --------------------------------------------------

is command_summary("a\nb"),
  [
    { command => 'a', argv => ['a'], before_op => undef, after_op => ';', context => [] },
    { command => 'b', argv => ['b'], before_op => ';',  after_op => undef, context => [] }
  ],
  'newline is normalised to ; operator';

# --- Semicolon-separated lists ------------------------------------------

is command_summary('a;b;c'),
  [
    { command => 'a', argv => ['a'], before_op => undef, after_op => ';', context => [] },
    { command => 'b', argv => ['b'], before_op => ';',  after_op => ';', context => [] },
    { command => 'c', argv => ['c'], before_op => ';',  after_op => undef, context => [] }
  ],
  'three-command semicolon chain';

# --- Negated command ----------------------------------------------------

is command_summary('! grep foo bar'),
  [
    { command => 'grep', argv => ['grep', 'foo', 'bar'], before_op => undef, after_op => undef, context => ['negated'] }
  ],
  '! prefix wraps command with negated context';

# `negated => 1` boolean on the command hash (2.2.2)
{
  my @cmds = $bash->commands('! grep foo bar');
  is scalar @cmds, 1, '! grep produces one command';
  ok $cmds[0]{negated}, '! grep command has negated => 1';
}

{
  my @cmds = $bash->commands('echo hi');
  is scalar @cmds, 1, 'plain echo produces one command';
  ok !exists $cmds[0]{negated}, 'plain echo does NOT have negated key';
}

{
  my @cmds = $bash->commands('echo a; ! echo b');
  is scalar @cmds, 2, 'two commands via semicolon';
  ok !exists $cmds[0]{negated}, 'first (non-negated) command has no negated key';
  ok $cmds[1]{negated}, 'second (negated) command has negated => 1';
}

{
  my @cmds = $bash->commands('! echo a && echo b');
  is scalar @cmds, 2, '! cmd && cmd: two commands';
  ok $cmds[0]{negated}, 'first command (after !) has negated => 1';
  ok !exists $cmds[1]{negated}, 'second command (after &&) has no negated key';
}

{
  my @cmds = $bash->commands('! (echo a; echo b)');
  is scalar @cmds, 2, '! (cmd; cmd): both commands extracted';
  ok $cmds[0]{negated}, 'first command inside negated subshell has negated => 1';
  ok $cmds[1]{negated}, 'second command inside negated subshell has negated => 1';
}

{
  my @cmds = $bash->commands('echo a | ! grep x');
  is scalar @cmds, 2, 'pipeline with negation';
  ok !exists $cmds[0]{negated}, 'first pipeline cmd has no negated key';
  ok $cmds[1]{negated}, 'second pipeline cmd has negated => 1';
}

{
  my @cmds = $bash->commands('! export FOO=bar');
  is scalar @cmds, 1, '! export produces one command';
  ok $cmds[0]{negated}, 'export inside ! has negated => 1';
}

{
  my @cmds = $bash->commands('! echo a > /tmp/x');
  is scalar @cmds, 1, '! with redirect produces one command';
  ok $cmds[0]{negated}, 'redirect inside ! has negated => 1';
}

# --- Subshell -----------------------------------------------------------

is command_summary('(echo a; echo b)'),
  [
    { command => 'echo', argv => ['echo', 'a'], before_op => undef, after_op => ';', context => ['subshell'] },
    { command => 'echo', argv => ['echo', 'b'], before_op => ';',  after_op => undef, context => ['subshell'] }
  ],
  'subshell commands are extracted with subshell context';

# --- Grouping -----------------------------------------------------------

is command_summary('{ echo a; echo b; }'),
  [
    { command => 'echo', argv => ['echo', 'a'], before_op => undef, after_op => ';', context => [] },
    { command => 'echo', argv => ['echo', 'b'], before_op => ';',  after_op => ';', context => [] }
  ],
  'brace group commands are extracted';

# --- Background ---------------------------------------------------------

is command_summary('sleep 10 &'),
  [
    { command => 'sleep', argv => ['sleep', '10'], before_op => undef, after_op => undef, context => [] }
  ],
  'background & does not produce a phantom second command';

# --- Declaration / unset / test commands --------------------------------

is command_summary('export FOO=bar'),
  [
    { command => 'export', argv => ['export', 'FOO=bar'], before_op => undef, after_op => undef, context => [] }
  ],
  'export becomes a declaration_command';

is command_summary('unset PATH'),
  [
    { command => 'unset', argv => ['unset', 'PATH'], before_op => undef, after_op => undef, context => [] }
  ],
  'unset becomes an unset_command';

# --- Process substitution ----------------------------------------------

is command_summary('diff <(cat a) <(cat b)'),
  [
    { command => 'diff', argv => ['diff'], before_op => undef, after_op => undef, context => [] },
    { command => 'cat',  argv => ['cat',  'a'], before_op => undef, after_op => undef, context => ['process_substitution'] },
    { command => 'cat',  argv => ['cat',  'b'], before_op => undef, after_op => undef, context => ['process_substitution'] }
  ],
  'process substitution creates nested command_substitutions';

# --- Nested pipelines ---------------------------------------------------

is command_summary('cat a | grep x | sort'),
  [
    { command => 'cat',  argv => ['cat',  'a'], before_op => undef, after_op => '|', context => ['pipeline'] },
    { command => 'grep', argv => ['grep', 'x'], before_op => '|',  after_op => '|', context => ['pipeline'] },
    { command => 'sort', argv => ['sort'],      before_op => '|',  after_op => undef, context => ['pipeline'] }
  ],
  'three-stage pipeline propagates operators correctly';

# --- Empty / undef input ------------------------------------------------

is [ $bash->commands('') ], [], 'empty string yields no commands';

eval { $bash->commands(undef) };
ok( $@, 'undef source croaks' );

# --- parse() returns a tree ---------------------------------------------

my $tree = $bash->parse('echo hi');
ok( $tree, 'parse returns a truthy tree' );
ok( $tree->can('root_node'), 'tree exposes root_node' );

# --- argv preserves quoting ---------------------------------------------

is command_summary(q{echo "hello world"}),
  [
    { command => 'echo', argv => [ 'echo', '"hello world"' ], before_op => undef, after_op => undef, context => [] }
  ],
  'quoted argv is preserved verbatim in argv';

is command_summary(q{echo 'hello world'}),
  [
    { command => 'echo', argv => [ 'echo', "'hello world'" ], before_op => undef, after_op => undef, context => [] }
  ],
  'single-quoted argv is preserved verbatim in argv';

done_testing;
