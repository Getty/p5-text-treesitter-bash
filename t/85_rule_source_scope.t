#!/usr/bin/env perl
use Test2::V0;
use Text::Treesitter::Bash::Security::Checker;
use Text::Treesitter::Bash::Security::Rule;

# EnvDangerousVars and UnquotedExpansion look at the text of one command
# only: not at quoted strings, paths or plain words that merely look like
# what they search for, and not at the commands nested inside it.

my $checker = Text::Treesitter::Bash::Security::Checker->new(
  rules => [qw( EnvDangerousVars UnquotedExpansion )],
);

sub count {
  my ( $source, $rule ) = @_;
  return scalar grep { $_->{rule} eq $rule } $checker->check_source($source);
}

subtest 'EnvDangerousVars: only assignments fire' => sub {
  for my $source (
    'echo "ENV is set"',
    'echo ENV',
    'grep IFS file',
    'cat /etc/ENV.conf',
    'echo hi > /tmp/IFS',
    'echo $LD_PRELOAD',
    'export LD_PRELOAD',
    q{echo 'say LD_PRELOAD=x'},
    'echo "say LD_PRELOAD=x"',
    'echo MY_LD_PRELOAD=x',
    "echo hi # LD_PRELOAD=x\n",
    "cat <<EOF\nLD_PRELOAD=x\nEOF",
  ) {
    is count( $source, 'EnvDangerousVars' ), 0, "no issue: $source";
  }

  for my $source (
    'LD_PRELOAD=/x.so ls',
    'export LD_PRELOAD=/x.so',
    'env "LD_PRELOAD=/x.so" ls',
    q{env 'LD_PRELOAD=/x.so' ls},
    'PATH=/bin LD_PRELOAD+=/x.so ls',
    'declare -x BASH_ENV=/tmp/x',
  ) {
    is count( $source, 'EnvDangerousVars' ), 1, "one issue: $source";
  }
};

subtest 'EnvDangerousVars: nested command is reported once, for itself' => sub {
  for my $source ( 'echo $(LD_PRELOAD=x ls)', 'echo "$(IFS=/ ls)"', 'echo `BASH_ENV=x ls`' ) {
    my @issues = grep { $_->{rule} eq 'EnvDangerousVars' } $checker->check_source($source);
    is scalar @issues, 1, "one issue: $source";
    is $issues[0]{command}, 'ls', '... for the nested command';
  }
};

subtest 'UnquotedExpansion: only where the shell splits' => sub {
  for my $source (
    'DIR=$HOME/bin',
    'export DIR=$HOME/bin',
    'declare -x DIR=$HOME/bin',
    'DIR=$HOME/bin cmd',
    '[[ $x == $HOME/* ]]',
    "cat <<EOF\n\$HOME/x\nEOF",
    'cat \$HOME/x',
    q{echo "$(echo '$HOME/x')"},
    q{echo "a'b" "$HOME/x"},
  ) {
    is count( $source, 'UnquotedExpansion' ), 0, "no issue: $source";
  }

  for my $source (
    'cat $HOME/x',
    'cat $HOME/x # $FOO/y',
    '[ -f $HOME/x ]',
    'env X=$HOME/y cmd',
    q{echo $'a\'b' $x/y},
    q{echo 'it''s' $x/y},
    "cat <<EOF \$HOME/x\nbody\nEOF",
  ) {
    is count( $source, 'UnquotedExpansion' ), 1, "one issue: $source";
  }
};

subtest 'UnquotedExpansion: nested command is reported once, for itself' => sub {
  for my $source ( 'echo $(cat $HOME/x)', 'echo `cat $HOME/x`', 'cat <(ls $HOME/x)', 'echo "$(cat $HOME/x)"' ) {
    my @issues = grep { $_->{rule} eq 'UnquotedExpansion' } $checker->check_source($source);
    is scalar @issues, 1, "one issue: $source";
    like $issues[0]{command}, qr/\A(?:cat|ls)\z/, '... for the nested command';
  }
};

subtest 'mask_source: same length, command level only' => sub {
  my $rule = 'Text::Treesitter::Bash::Security::Rule';

  for my $source (
    q{echo "a b" 'c d' $(x y) `z` <(w) # note},
    "cat <<-EOF\n\tbody \$(x)\n\tEOF\nnext",
    q{echo \\" "a\\"b" $'c\\'d' ${x:-"y z"} $((1+2))},
    'echo "unterminated $(x',
    'trailing \\',
    q{},
  ) {
    my ( $words, $unquoted ) = $rule->mask_source($source);
    is [ length $words, length $unquoted ], [ (length $source) x 2 ], 'same length: ' . ( $source =~ s/\n/\\n/gr );
  }

  my ( $words, $unquoted ) = $rule->mask_source(q{echo "a b" $(x y) z});
  is $words,    "echo \"a\x01b\"" . ( q{ } x 8 ) . 'z', 'quoted blank is one word, substitution blanked';
  is $unquoted, 'echo' . ( q{ } x 14 ) . 'z',           'quoted text blanked as well';
};

done_testing;
