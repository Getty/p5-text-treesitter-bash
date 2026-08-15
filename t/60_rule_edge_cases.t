use Test2::V0;
use Text::Treesitter::Bash::Security::Checker;

my $checker = Text::Treesitter::Bash::Security::Checker->new(
  rules => [qw( PathTraversal DangerousFlags SensitiveAccess EnvDangerousVars UnquotedExpansion MissingAbsolutePath )]
);

sub has_rule {
  my ( $source, $rule ) = @_;
  my @issues = $checker->check_source($source);
  return scalar( grep { $_->{rule} eq $rule } @issues );
}

# --- DangerousFlags: variants ------------------------------------------

ok( has_rule('rm -rf /tmp/x',         'DangerousFlags'), 'rm -rf combined flag triggers' );
ok( has_rule('rm -fr /tmp/x',         'DangerousFlags'), 'rm -fr (reversed order) triggers' );
ok( has_rule('rm --force --recursive /tmp/x', 'DangerousFlags'), 'long flags trigger' );
ok( has_rule('rm --recursive --force /tmp/x', 'DangerousFlags'), 'long flags reversed trigger' );
ok(!has_rule('rm -r /tmp/x',           'DangerousFlags'), 'rm -r alone does NOT trigger high' );
ok(!has_rule('rm -f /tmp/x',           'DangerousFlags'), 'rm -f alone does NOT trigger high' );

# --- PathTraversal: edge cases ------------------------------------------

ok( has_rule('cat /etc/../etc/shadow', 'PathTraversal'), '../ path traversal' );
ok( has_rule('cat /proc/../foo',       'PathTraversal'), 'proc traversal' );
ok( has_rule('cat /sys/../foo',        'PathTraversal'), 'sys traversal' );
ok( has_rule('cat /proc/self/maps',    'PathTraversal'), 'proc/self introspection (medium)' );
ok(!has_rule('cat /tmp/foo',           'PathTraversal'), 'normal path does not trigger PathTraversal' );

# --- SensitiveAccess: coverage ------------------------------------------

ok( has_rule('cat /etc/shadow',         'SensitiveAccess'), 'shadow file' );
ok( has_rule('cat /etc/sudoers',        'SensitiveAccess'), 'sudoers file' );
ok( has_rule('ls ~/.ssh/',              'SensitiveAccess'), 'ssh dir' );
ok( has_rule('ls ~/.aws/',              'SensitiveAccess'), 'aws dir' );
ok( has_rule('ls ~/.kube/',             'SensitiveAccess'), 'kube dir' );
ok( has_rule('cat /etc/passwd',         'SensitiveAccess'), 'passwd file' );
ok( has_rule('cat /etc/group',          'SensitiveAccess'), 'group file' );
ok( has_rule('cat /proc/self/status',   'SensitiveAccess'), 'proc/self' );
ok( has_rule('cat /sys/fs/',            'SensitiveAccess'), 'sys/fs' );
ok( has_rule('cat /dev/null',           'SensitiveAccess'), 'dev access' );
ok(!has_rule('ls /home/user',           'SensitiveAccess'), 'home dir does not trigger' );

# --- EnvDangerousVars: coverage -----------------------------------------

ok( has_rule('LD_PRELOAD=/x.so ls',                 'EnvDangerousVars'), 'LD_PRELOAD' );
ok( has_rule('LD_AUDIT=/x.so ls',                   'EnvDangerousVars'), 'LD_AUDIT' );
ok( has_rule('DYLD_INSERT_LIBRARIES=/x.dylib ls',   'EnvDangerousVars'), 'DYLD_INSERT_LIBRARIES' );
ok( has_rule('DYLD_LIBRARY_PATH=/x ls',             'EnvDangerousVars'), 'DYLD_LIBRARY_PATH' );
ok( has_rule('BASH_ENV=/tmp/x.sh ls',               'EnvDangerousVars'), 'BASH_ENV' );
ok( has_rule('ENV=/tmp/x.sh bash',                  'EnvDangerousVars'), 'ENV' );
ok( has_rule('CDPATH=/x cd',                        'EnvDangerousVars'), 'CDPATH' );
ok( has_rule('GIT_DIR=/x git status',               'EnvDangerousVars'), 'GIT_DIR' );
ok( has_rule('export LD_PRELOAD=/x.so ls',          'EnvDangerousVars'), 'exported LD_PRELOAD' );
ok(!has_rule('echo PATH=$PATH',                     'EnvDangerousVars'), 'PATH is not dangerous' );

# --- UnquotedExpansion: edge cases -------------------------------------

ok( has_rule('cat $HOME/.ssh/id_rsa',           'UnquotedExpansion'), 'unquoted $VAR before path char' );
ok( has_rule('rm -rf $TMPDIR/cache',            'UnquotedExpansion'), 'unquoted $VAR before -' );
ok( has_rule('echo $NAME.txt',                  'UnquotedExpansion'), 'unquoted $VAR before .' );
ok(!has_rule('echo "$HOME"',                    'UnquotedExpansion'), 'quoted var does not trigger' );
ok(!has_rule('echo done',                       'UnquotedExpansion'), 'no var, no trigger' );

# --- MissingAbsolutePath ------------------------------------------------

ok(!has_rule('/usr/bin/rm -rf /tmp/x', 'MissingAbsolutePath'), 'absolute path OK' );
ok(!has_rule('./script.sh',             'MissingAbsolutePath'), 'relative dot OK' );
ok(!has_rule('../script.sh',            'MissingAbsolutePath'), 'relative dotdot OK' );
ok(!has_rule('rm -rf /tmp/x',           'MissingAbsolutePath'), 'rm in allowlist OK' );
ok(!has_rule('ls -la /tmp',             'MissingAbsolutePath'), 'ls in allowlist OK' );
ok(!has_rule('echo hi',                 'MissingAbsolutePath'), 'builtin-ish OK' );
ok( has_rule('weirdtool foo bar',       'MissingAbsolutePath'), 'unknown command without path triggers' );

# --- Severity sanity ----------------------------------------------------

subtest 'severity values are low/medium/high' => sub {
  my @issues = $checker->check_source('LD_PRELOAD=/x.so rm -rf /tmp/x && cat /etc/shadow');
  for my $i (@issues) {
    like $i->{severity}, qr/^(low|medium|high)$/, "$i->{rule} severity is valid";
  }
};

# --- Empty / safe input -------------------------------------------------

is [ $checker->check_source('') ], [], 'empty source yields no issues';
is [ $checker->check_source('echo safe command') ], [], 'safe command yields no issues';

done_testing;
