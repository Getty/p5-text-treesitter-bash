use Test2::V0;
use Text::Treesitter::Bash::Security::Checker;

my $checker = Text::Treesitter::Bash::Security::Checker->new(
  rules => ['SensitiveRedirect'],
);

sub has_rule {
  my ( $source, $rule ) = @_;
  my @issues = $checker->check_source($source);
  return scalar( grep { $_->{rule} eq $rule } @issues );
}

sub severity_of {
  my ( $source, $rule ) = @_;
  my @issues = $checker->check_source($source);
  my ($i) = grep { $_->{rule} eq $rule } @issues;
  return $i ? $i->{severity} : undef;
}

# --- High severity: credential stores + block devices -------------------

ok( has_rule('echo hi > /etc/passwd', 'SensitiveRedirect'),    '> /etc/passwd' );
ok( has_rule('echo hi >> /etc/shadow', 'SensitiveRedirect'),   '>> /etc/shadow' );
ok( has_rule('echo hi > /etc/sudoers', 'SensitiveRedirect'),   '> /etc/sudoers' );
ok( has_rule('echo hi > /dev/sda', 'SensitiveRedirect'),       '> /dev/sda' );
ok( has_rule('echo hi > /dev/nvme0n1', 'SensitiveRedirect'),   '> /dev/nvme0n1' );
ok( has_rule('echo hi > /dev/vda', 'SensitiveRedirect'),       '> /dev/vda' );
ok( has_rule('echo hi > /dev/mmcblk0', 'SensitiveRedirect'),   '> /dev/mmcblk0' );
ok( has_rule('echo hi > ~/.ssh/known_hosts', 'SensitiveRedirect'), '> ~/.ssh' );
ok( has_rule('echo hi > ~/.aws/credentials', 'SensitiveRedirect'), '> ~/.aws' );
ok( has_rule('echo hi > ~/.kube/config', 'SensitiveRedirect'), '> ~/.kube' );
ok( has_rule('echo hi > ~/.gnupg/foo', 'SensitiveRedirect'),   '> ~/.gnupg' );

is( severity_of('echo hi > /etc/passwd', 'SensitiveRedirect'), 'high',
  'credential store redirect is high' );

# --- Medium severity: system config / log / history --------------------

ok( has_rule('echo hi > /etc/hosts', 'SensitiveRedirect'),         '> /etc/hosts' );
ok( has_rule('echo hi > ~/.bash_history', 'SensitiveRedirect'),    '> ~/.bash_history' );
ok( has_rule('echo hi > /var/log/messages', 'SensitiveRedirect'),  '> /var/log' );
is( severity_of('echo hi > /etc/hosts', 'SensitiveRedirect'), 'medium',
  'system config redirect is medium' );

# --- Low: standard device files ----------------------------------------

is( severity_of('echo hi > /dev/null', 'SensitiveRedirect'), 'low',
  '/dev/null is low' );

# --- Negative cases ----------------------------------------------------

ok( !has_rule('echo hi > /tmp/out', 'SensitiveRedirect'), '> /tmp/out is benign' );
ok( !has_rule('echo hi > ./output.txt', 'SensitiveRedirect'), '> ./output.txt is benign' );
ok( !has_rule('echo hi', 'SensitiveRedirect'), 'no redirect → no finding' );

# --- Reads ------------------------------------------------------------

ok( has_rule('cmd < /etc/shadow', 'SensitiveRedirect'),
  '< /etc/shadow (read of credential store)' );

done_testing;
