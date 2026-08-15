use Test2::V0;
use Text::Treesitter::Bash;
use Text::Treesitter::Bash::Security::Checker;

my $bash = Text::Treesitter::Bash->new;

sub get_commands {
  my ($source) = @_;
  return [ $bash->commands($source) ];
}

my $checker = Text::Treesitter::Bash::Security::Checker->new(
  rules => [qw(
    PathTraversal DangerousFlags UnquotedExpansion
  )],
);

sub has_rule {
  my ( $source, $rule ) = @_;
  my @issues = $checker->check_source($source);
  return scalar( grep { $_->{rule} eq $rule } @issues );
}

# --- 2.2.1: subshell before_op propagation -----------------------------

is( get_commands('cmd1 && (cmd2; cmd3)')->[1]{before_op}, '&&',
  'subshell first inner command inherits outer before_op' );

is( get_commands('foo || (bar; baz)')->[1]{before_op}, '||',
  'subshell first inner command inherits outer ||' );

is( get_commands('foo; (bar; baz)')->[1]{before_op}, ';',
  'subshell first inner command inherits outer ;' );

is( get_commands('cmd1 && (cmd2; cmd3)')->[1]{context}, ['subshell'],
  'inner command has subshell context' );

# Same for process_substitution and command_substitution wrappers
is( get_commands('foo && diff <(cat a) <(cat b)')->[1]{before_op}, '&&',
  'process_substitution first inner command inherits outer before_op' );

# --- 2.5.5: PathTraversal generic `..` matching ------------------------

ok( has_rule('cat /foo/../bar', 'PathTraversal'),
  'PathTraversal: /foo/../bar (mid-path ..)' );

ok( has_rule('cat /a/b/..', 'PathTraversal'),
  'PathTraversal: /a/b/.. (trailing ..)' );

ok( has_rule('cat ..', 'PathTraversal'),
  'PathTraversal: standalone ..' );

ok( has_rule('cat ../foo', 'PathTraversal'),
  'PathTraversal: ../foo' );

ok( has_rule('cat /etc/foo/../shadow', 'PathTraversal'),
  'PathTraversal: /etc/foo/../shadow (mid-path .. NOT under /etc/../)' );

ok( !has_rule('cat /etc/hosts', 'PathTraversal'),
  'PathTraversal: clean /etc/hosts does NOT trigger' );

ok( has_rule('cat /proc/self/cmdline', 'PathTraversal'),
  'PathTraversal: /proc/self introspection triggers medium' );

ok( has_rule('cat /proc/$$/status', 'PathTraversal'),
  'PathTraversal: /proc/$$ introspection triggers medium' );

ok( has_rule('cat /sys/fs/cgroup/memory', 'PathTraversal'),
  'PathTraversal: /sys/fs triggers medium' );

# --- 2.5.7: UnquotedExpansion per-Variable -----------------------------

ok( has_rule('echo "safe $foo" $bar/baz', 'UnquotedExpansion'),
  'UnquotedExpansion: $bar/baz triggers even when "$foo" is in source' );

my @mixed_issues = $checker->check_source('echo "safe $foo" $bar/baz');
is( scalar @mixed_issues, 1,
  'UnquotedExpansion: only one issue reported when mixed quoted/unquoted' );
is( $mixed_issues[0]{var}, '$bar',
  'UnquotedExpansion: only $bar is reported, $foo in quotes is ignored' );

ok( !has_rule(q{echo '$foo'}, 'UnquotedExpansion'),
  'UnquotedExpansion: single-quoted $foo does NOT trigger' );

ok( has_rule('rm -rf $TMPDIR/cache', 'UnquotedExpansion'),
  'UnquotedExpansion: $TMPDIR/cache at slash triggers' );

ok( has_rule('cat $HOME/.ssh/id_rsa', 'UnquotedExpansion'),
  'UnquotedExpansion: $HOME/.ssh/id_rsa triggers' );

ok( !has_rule('echo $foo', 'UnquotedExpansion'),
  'UnquotedExpansion: bare $foo without path-delimiter does NOT trigger' );

ok( !has_rule('echo "${var}/foo"', 'UnquotedExpansion'),
  'UnquotedExpansion: ${var} inside double-quotes does NOT trigger' );

# --- 2.2.3: redirects field is populated -------------------------------

sub redirects {
  my ($source) = @_;
  my @cmds = $bash->commands($source);
  return $cmds[0]{redirects} // [];
}

is( redirects('echo hi > /etc/passwd'),
  [ { type => 'file_redirect', operator => '>', target => '/etc/passwd', text => '> /etc/passwd' } ],
  'redirects: capture > target' );

is( redirects('echo hi >> /etc/passwd'),
  [ { type => 'file_redirect', operator => '>>', target => '/etc/passwd', text => '>> /etc/passwd' } ],
  'redirects: capture >> target' );

is( redirects('cmd < /etc/shadow'),
  [ { type => 'file_redirect', operator => '<', target => '/etc/shadow', text => '< /etc/shadow' } ],
  'redirects: capture < target' );

is( redirects('echo hi 2>&1'),
  [ { type => 'file_redirect', operator => '2>&', target => '1', text => '2>&1' } ],
  'redirects: capture 2>&1 descriptor + target' );

is( redirects('cmd 2>/dev/null'),
  [ { type => 'file_redirect', operator => '2>', target => '/dev/null', text => '2>/dev/null' } ],
  'redirects: capture 2> descriptor + target' );

is( redirects('cat <<< "hello world"'),
  [ { type => 'herestring_redirect', operator => '<<<', target => '"hello world"', text => '<<< "hello world"' } ],
  'redirects: capture <<< herestring' );

is( redirects("cat <<EOF\nfoo\nbar\nEOF"),
  [ { type => 'heredoc_redirect', operator => '<<', target => 'EOF', text => "<<EOF\nfoo\nbar\nEOF" } ],
  'redirects: capture << heredoc start marker' );

is( scalar @{ redirects('echo hi > /dev/null 2>&1') }, 2,
  'redirects: multiple redirects on one command' );

is( redirects('echo hi'),
  [],
  'redirects: empty array when no redirects' );

done_testing;
