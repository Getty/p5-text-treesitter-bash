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
ok( has_rule('rm -fR /tmp/x',         'DangerousFlags'), 'rm -fR (capital R) triggers' );
ok( has_rule('rm -FR /tmp/x',         'DangerousFlags'), 'rm -FR (capital both) triggers' );
ok( has_rule('rm -RF /tmp/x',         'DangerousFlags'), 'rm -RF (capital R first) triggers' );
ok( has_rule('rm --force --recursive /tmp/x', 'DangerousFlags'), 'long flags trigger' );
ok( has_rule('rm --recursive --force /tmp/x', 'DangerousFlags'), 'long flags reversed trigger' );
ok( has_rule('cp -rf src dst',        'DangerousFlags'), 'cp -rf triggers (whitelist)' );
ok( has_rule('mv -rf src dst',        'DangerousFlags'), 'mv -rf triggers (whitelist)' );
ok(!has_rule('rm -r /tmp/x',           'DangerousFlags'), 'rm -r alone does NOT trigger high' );
ok(!has_rule('rm -f /tmp/x',           'DangerousFlags'), 'rm -f alone does NOT trigger high' );
ok(!has_rule('ls -rf',                 'DangerousFlags'), 'ls -rf does NOT trigger (not destructive)' );
ok(!has_rule('gcc -fR foo',            'DangerousFlags'), 'gcc -fR does NOT trigger (not destructive)' );

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
ok(!has_rule('cat /dev/null',           'SensitiveAccess'), '/dev/null is whitelisted' );
ok(!has_rule('cat /dev/zero',           'SensitiveAccess'), '/dev/zero is whitelisted' );
ok(!has_rule('cat /dev/stdin',          'SensitiveAccess'), '/dev/stdin is whitelisted' );
ok( has_rule('cat /dev/sda',            'SensitiveAccess'), 'non-whitelisted /dev/ still triggers' );
ok( has_rule('cat /dev/disk0',          'SensitiveAccess'), '/dev/disk0 (macOS) triggers' );
ok( has_rule('cat /dev/loop0',          'SensitiveAccess'), '/dev/loop0 triggers' );
ok(!has_rule('ls /home/user',           'SensitiveAccess'), 'home dir does not trigger' );

# --- SensitiveAccess: extended credential / daemon / browser coverage (2.5.15) ---

ok( has_rule('cat ~/.pgpass',                      'SensitiveAccess'), 'pgpass credentials' );
ok( has_rule('ls /var/run/docker.sock',            'SensitiveAccess'), 'docker daemon socket' );
ok( has_rule('modprobe /lib/modules/5.10/nvme.ko', 'SensitiveAccess'), 'kernel module path' );
ok( has_rule('ls ~/Library/Keychains/login.keychain-db', 'SensitiveAccess'), 'macOS Keychain' );
ok( has_rule('ls ~/.config/google-chrome/Default/Bookmarks', 'SensitiveAccess'), 'Chrome profile' );
ok( has_rule('ls ~/.config/chromium/Default',      'SensitiveAccess'), 'Chromium profile' );
ok( has_rule('ls ~/.mozilla/firefox/profiles.ini', 'SensitiveAccess'), 'Firefox profile' );
ok( has_rule('ls ~/.cache/google-chrome/Default',   'SensitiveAccess'), 'Chrome cache' );
ok( has_rule('cat /etc/gshadow',                   'SensitiveAccess'), 'group shadow file' );
ok( has_rule('cat /proc/1234/environ',              'SensitiveAccess'), 'process environ' );

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

# --- EnvDangerousVars: extended coverage (2.5.13) ----------------------

ok( has_rule('SHELLOPTS=allexec bash',              'EnvDangerousVars'), 'SHELLOPTS' );
ok( has_rule(q{BASH_FUNC_foo bash},                'EnvDangerousVars'), 'BASH_FUNC_ prefix triggers' );
ok( has_rule('IFS=/ cat /etc/passwd',               'EnvDangerousVars'), 'IFS assignment' );
ok( has_rule('PROMPT_COMMAND=id bash',              'EnvDangerousVars'), 'PROMPT_COMMAND' );
ok( has_rule('PS4="\$(reboot)" bash',               'EnvDangerousVars'), 'PS4 with expansion' );
ok( has_rule('PYTHONPATH=/evil python',             'EnvDangerousVars'), 'PYTHONPATH' );
ok( has_rule('PYTHONSTARTUP=/evil/x.py python',     'EnvDangerousVars'), 'PYTHONSTARTUP' );
ok( has_rule('NODE_PATH=/evil node x.js',           'EnvDangerousVars'), 'NODE_PATH' );
ok( has_rule('NODE_OPTIONS="--require evil" node',  'EnvDangerousVars'), 'NODE_OPTIONS' );
ok( has_rule('PERL5LIB=/evil perl -e 1',            'EnvDangerousVars'), 'PERL5LIB' );
ok( has_rule('PERL5OPT="-Mevil" perl -e 1',         'EnvDangerousVars'), 'PERL5OPT' );
ok( has_rule('RUBYLIB=/evil ruby -e 1',             'EnvDangerousVars'), 'RUBYLIB' );
ok( has_rule('RUBYOPT="-revenv" ruby -e 1',         'EnvDangerousVars'), 'RUBYOPT' );
ok( has_rule('CLASSPATH=/evil java Foo',            'EnvDangerousVars'), 'CLASSPATH' );
ok( has_rule('LD_LIBRARY_PATH=/evil ls',            'EnvDangerousVars'), 'LD_LIBRARY_PATH' );
ok( has_rule('GIT_WORK_TREE=/x git status',         'EnvDangerousVars'), 'GIT_WORK_TREE' );
ok( has_rule('GIT_INDEX_FILE=/x/foo git status',    'EnvDangerousVars'), 'GIT_INDEX_FILE' );

# --- UnquotedExpansion: edge cases -------------------------------------

ok( has_rule('cat $HOME/.ssh/id_rsa',           'UnquotedExpansion'), 'unquoted $VAR before path char' );
ok( has_rule('rm -rf $TMPDIR/cache',            'UnquotedExpansion'), 'unquoted $VAR before -' );
ok( has_rule('echo $NAME.txt',                  'UnquotedExpansion'), 'unquoted $VAR before .' );
ok(!has_rule('echo "$HOME"',                    'UnquotedExpansion'), 'quoted var does not trigger' );
ok(!has_rule('echo done',                       'UnquotedExpansion'), 'no var, no trigger' );

# --- UnquotedExpansion: brace and arithmetic forms (2.5.10) -----------

ok( has_rule('cat ${HOME}/.ssh/id_rsa',         'UnquotedExpansion'), '${HOME} brace form triggers' );
ok( has_rule('rm -rf ${TMPDIR}/cache',          'UnquotedExpansion'), '${TMPDIR} brace form triggers' );
ok( has_rule('cat ${var:-default}/file',        'UnquotedExpansion'), '${var:-default} brace-default triggers' );
ok( has_rule('cat $((1+2))/foo',                'UnquotedExpansion'), '$((expr)) arithmetic triggers' );
ok(!has_rule('echo "${HOME}/path"',             'UnquotedExpansion'), 'quoted ${HOME} does not trigger' );

# --- MissingAbsolutePath ------------------------------------------------

ok(!has_rule('/usr/bin/rm -rf /tmp/x', 'MissingAbsolutePath'), 'absolute path OK' );
ok(!has_rule('./script.sh',             'MissingAbsolutePath'), 'relative dot OK' );
ok(!has_rule('../script.sh',            'MissingAbsolutePath'), 'relative dotdot OK' );
ok(!has_rule('rm -rf /tmp/x',           'MissingAbsolutePath'), 'rm in allowlist OK' );
ok(!has_rule('ls -la /tmp',             'MissingAbsolutePath'), 'ls in allowlist OK' );
ok(!has_rule('echo hi',                 'MissingAbsolutePath'), 'builtin-ish OK' );
ok( has_rule('weirdtool foo bar',       'MissingAbsolutePath'), 'unknown command without path triggers' );

# --- MissingAbsolutePath: edge cases (2.5.17/18) -----------------------

ok( has_rule('cmd/subcmd arg',          'MissingAbsolutePath'), 'relative cmd/subcmd triggers' );
ok( has_rule('foo/bar baz',             'MissingAbsolutePath'), 'foo/bar triggers' );
ok(!has_rule('1foo bar',                'MissingAbsolutePath'), 'non-identifier name skipped' );
ok(!has_rule('echo $x',                 'MissingAbsolutePath'), 'builtin name with expansion skipped' );

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
