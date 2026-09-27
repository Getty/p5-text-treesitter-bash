use Test2::V0;
use File::Temp qw( tempdir );
use Path::Tiny qw( path );
use Text::Treesitter::Bash;
use Text::Treesitter::Bash::Security::Checker;

# The vendored grammar is copied and compiled at most once per process:
# every Text::Treesitter::Bash instance and every check_source call
# shares that build. Before, each instance copied ~10 MB into a fresh
# tempdir and ran gcc, and the dirs piled up in TMPDIR until exit.

# Private TMPDIR, so the grammar tempdirs of this process can be counted.
# File::Temp removes it, with everything inside, at exit.
my $tmp = path( tempdir( 'grammar-build-once-XXXXXX', TMPDIR => 1, CLEANUP => 1 ) );
$ENV{TMPDIR} = $tmp->stringify;

sub grammar_dirs {
  return [ map { $_->stringify } $tmp->children( qr/\Atext-treesitter-bash-/ ) ];
}

sub command_names {
  my ( $bash, $source ) = @_;
  return [ map { $_->{command} } $bash->commands($source) ];
}

# Record every grammar build by the .so it produces.
my @builds;
my $real_build = \&Text::Treesitter::Language::build;
{
  no warnings 'redefine';
  *Text::Treesitter::Language::build = sub { push @builds, $_[0]; goto &$real_build };
}

subtest 'check_source builds the grammar once' => sub {
  my $checker = Text::Treesitter::Bash::Security::Checker->new( rules => ['DangerousFlags'] );
  my ( $calls, $hits, $first_dirs ) = ( 0, 0 );
  for my $i ( 1 .. 20 ) {
    $calls++;
    $hits++ if grep { $_->{rule} eq 'DangerousFlags' } $checker->check_source( 'rm -rf /tmp/x'.$i );
    $first_dirs //= grammar_dirs();
    # A regression costs a gcc run and ~13 MB of TMPDIR per call; stop
    # as soon as it shows instead of filling a small /tmp.
    last if @builds > 1;
  }
  is $calls, 20, 'all calls ran';
  is $hits, 20, 'every call still reports the issue';
  is scalar @builds, 1, 'grammar compiled exactly once';
  is scalar @$first_dirs, 1, 'one grammar tempdir after the first call';
  is grammar_dirs(), $first_dirs, 'no further tempdir after the first call';
};

subtest 'separate instances share the build' => sub {
  my $before = grammar_dirs();
  for my $i ( 1 .. 5 ) {
    is command_names( Text::Treesitter::Bash->new, 'ls -la | wc -l' ), [qw( ls wc )],
      'instance '.$i.' parses';
    last if @builds > 1;
  }
  is scalar @builds, 1, 'still compiled exactly once';
  is grammar_dirs(), $before, 'no further tempdir';
};

# The remaining cases need a build but not another gcc run: the
# stand-in build copies the grammar compiled above.
my $compiled = path( tempdir( 'compiled-XXXXXX', TMPDIR => 1, CLEANUP => 1 ) )
  ->child('tree-sitter-bash.so');
path( $builds[0] )->copy($compiled);

sub copy_build { push @builds, $_[0]; $compiled->copy( $_[0] ) }

subtest 'explicit lang_dir builds into that directory' => sub {
  no warnings 'redefine';
  local *Text::Treesitter::Language::build = \&copy_build;

  my $own    = path( tempdir( 'own-grammar-XXXXXX', TMPDIR => 1, CLEANUP => 1 ) );
  my $before = grammar_dirs();
  my $bash   = Text::Treesitter::Bash->new( lang_dir => $own->stringify );

  is command_names( $bash, 'echo hi' ), ['echo'], 'parses';
  is scalar @builds, 2, 'built once';
  is $builds[-1], $own->child('tree-sitter-bash.so')->stringify, 'into the given lang_dir';
  is grammar_dirs(), $before, 'no grammar tempdir for an explicit lang_dir';
};

subtest 'a vanished grammar build is replaced' => sub {
  no warnings 'redefine';
  local *Text::Treesitter::Language::build = \&copy_build;

  # What a forked child sees once the parent exited and File::Temp
  # removed its tempdir, or a long-running process after a tmpfiles sweep.
  my ($old) = @{ grammar_dirs() };
  path($old)->remove_tree;

  is command_names( Text::Treesitter::Bash->new, 'echo hi' ), ['echo'], 'parses again';
  is scalar @builds, 3, 'rebuilt once';
  my $dirs = grammar_dirs();
  is scalar @$dirs, 1, 'into one fresh grammar tempdir';
  isnt $dirs->[0], $old, 'not the vanished one';

  is command_names( Text::Treesitter::Bash->new, 'echo hi' ), ['echo'], 'next instance parses';
  is scalar @builds, 3, 'and shares the new build';
  is grammar_dirs(), $dirs, 'no further tempdir';
};

subtest 'a failing build is retried in the same tempdir' => sub {
  no warnings 'redefine';

  # Start over, so the next use copies the grammar and builds afresh.
  my ($old) = @{ grammar_dirs() };
  path($old)->remove_tree;

  my $dirs;
  {
    # A broken toolchain (no gcc, missing headers): no .so appears.
    local *Text::Treesitter::Language::build = sub { push @builds, $_[0]; return };
    for my $i ( 1 .. 3 ) {
      like dies { Text::Treesitter::Bash->new->commands('echo hi') },
        qr/\AFailed to build tree-sitter-bash grammar at /, 'call '.$i.' croaks';
      $dirs //= grammar_dirs();
    }
  }
  is scalar @builds, 6, 'every call retried the build';
  is scalar @$dirs, 1, 'one grammar tempdir after the first failure';
  is grammar_dirs(), $dirs, 'no further tempdir after it';

  local *Text::Treesitter::Language::build = \&copy_build;
  is command_names( Text::Treesitter::Bash->new, 'echo hi' ), ['echo'], 'parses once the build works';
  is scalar @builds, 7, 'built once more';
  is grammar_dirs(), $dirs, 'in that same tempdir';
};

done_testing;
