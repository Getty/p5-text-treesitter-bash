use Test2::V0;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Text::Treesitter::Bash::Security::Checker;
use Text::Treesitter::Bash::Security::Rule;

# --- 2.6.3: validate `check` method on registration --------------------

{
  my $err = dies {
    Text::Treesitter::Bash::Security::Checker->new(
      rules => ['PathTraversal', 'NoSuchRule']
    );
  };
  like $err, qr/NoSuchRule/, 'unknown rule class croaks with class name';
}

# --- 2.6.1: defensive filter against `undef` returns -------------------
# Module::Load::load requires the rule class to live on disk. We
# materialise three minimal .pm files in a temp dir, then push it onto
# @INC.

my $rule_dir = path( tempdir( CLEANUP => 1 ) );
$rule_dir->mkpath;

for my $rule (
  [ 'ReturnsUndef',    'return undef;' ],
  [ 'ReturnsBareList', q{
    return (
      { rule => 'TestRule', severity => 'low',    message => 'issue 1' },
      { rule => 'TestRule', severity => 'medium', message => 'issue 2' },
    );
  } ],
  [ 'ReturnsEmptyList', 'return ();' ],
  ) {
  my ( $name, $body ) = @$rule;
  my $pkg = "Text::Treesitter::Bash::Security::Rule::$name";
  my $path = $pkg;
  $path =~ s{::}{/}g;
  my $file = $rule_dir->child( $path . '.pm' );
  $file->parent->mkpath;
  $file->spew(<<"EOF");
package $pkg;
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';
sub check { $body }
1;
EOF
}

unshift @INC, $rule_dir->stringify;

my $checker = Text::Treesitter::Bash::Security::Checker->new(
  rules => [
    'ReturnsUndef',
    'ReturnsEmptyList',
    'ReturnsBareList',
  ],
);

my @issues = $checker->check_source('echo hi');

is( scalar @issues, 2,
  'rule returning undef does NOT corrupt the issue list (only 2 hashrefs survive)' );

is( $issues[0]{message}, 'issue 1', 'first valid issue preserved' );
is( $issues[1]{message}, 'issue 2', 'second valid issue preserved' );

done_testing;
