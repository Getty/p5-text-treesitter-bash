package Text::Treesitter::Bash::Security::Checker;
# ABSTRACT: Run security rules against parsed Bash commands
our $VERSION = '0.002';
use strict;
use warnings;
use Carp qw( croak );
use Module::Load qw( load );

sub new {
  my ( $class, %args ) = @_;

  my @rules = @{ $args{rules} // [] };
  my @instances;

  for my $rule (@rules) {
    if ( !ref $rule ) {
      my $class_name = "Text::Treesitter::Bash::Security::Rule::$rule";
      load($class_name);
      $rule = $class_name;
    }
    push @instances, $rule;
  }

  return bless { rules => \@instances }, $class;
}

sub check_commands {
  my ( $self, @commands ) = @_;

  my @issues;

  for my $command (@commands) {
    for my $rule ( @{ $self->{rules} } ) {
      my @result = $rule->check($command);
      push @issues, @result if @result;
    }
  }

  return @issues;
}

sub check_source {
  my ( $self, $source ) = @_;

  require Text::Treesitter::Bash;
  my $bash = Text::Treesitter::Bash->new;
  my @commands = $bash->commands($source);

  return $self->check_commands(@commands);
}

1;