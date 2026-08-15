package Text::Treesitter::Bash::Security::Rule::DangerousFilesystem;
# ABSTRACT: Detect dangerous filesystem commands (disk wipe, raw write to devices, etc.)
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::DangerousFilesystem - detect disk wipe / raw-device writes / destructive redirects

=head1 DESCRIPTION

C<high> severity matches:

=over 4

=item C<dd of=/dev/sdX>, C<of=/dev/nvme0n1> — writing to a block device.

=item C<mkfs>, C<mkfs.ext4>, C<mkfs.xfs>, etc. — format a filesystem.

=item C<parted>, C<fdisk>, C<gdisk>, C<sfdisk> — partitioning tools.

=item C<: > /etc/...>, C<truncate -s 0> — wipe system files via redirect / truncate.

=item C<shred> — secure delete of a file.

=back

C<medium> matches:

=over 4

=item C<mount>, C<umount> — mount-table manipulation.

=item C<losetup>, C<cryptsetup> — loop/crypto device setup.

=back

=head1 EXAMPLES

    dd if=/dev/zero of=/dev/sda                -> high
    mkfs.ext4 /dev/sdb1                        -> high
    : > /etc/passwd                            -> high
    truncate -s 0 /var/log/auth.log            -> high
    shred -u ~/.bash_history                   -> medium

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

sub check {
  my ( $class, $command ) = @_;

  my $name = $command->{command} // '';
  my $argv = $command->{argv} // [];
  my $source = $command->{source} // '';

  my $basename = $name;
  $basename =~ s{.*/}{};

  # dd of=/dev/...
  if ( $basename eq 'dd' ) {
    for my $arg (@$argv) {
      next if ref $arg;
      if ( $arg =~ m{^of=(/dev/|/proc/|/sys/)} ) {
        return {
          rule     => 'DangerousFilesystem',
          severity => 'high',
          message  => "Raw write to device: $arg",
          command  => $name,
          arg      => $arg,
        };
      }
    }
  }

  # mkfs* / fdisk / parted / gdisk / sfdisk
  if ( $basename =~ m{\A(?:mkfs(?:\.\w+)?|fdisk|parted|gdisk|sfdisk|wipefs)\z} ) {
    return {
      rule     => 'DangerousFilesystem',
      severity => 'high',
      message  => "Filesystem / partition tool: $basename",
      command  => $name,
      argv     => $argv,
    };
  }

  # : > /etc/...
  if ( $source =~ m{:\s*>\s*/etc/} ) {
    return {
      rule     => 'DangerousFilesystem',
      severity => 'high',
      message  => "Destructive redirect into /etc",
      command  => $name,
      source   => $source,
    };
  }

  # truncate -s 0 /var/log/... or /etc/...
  if ( $basename eq 'truncate' ) {
    for my $arg (@$argv) {
      next if ref $arg;
      if ( $arg =~ m{^(?:/etc/|/var/log/|/boot/|/usr/)} ) {
        return {
          rule     => 'DangerousFilesystem',
          severity => 'high',
          message  => "Truncate of system path: $arg",
          command  => $name,
          arg      => $arg,
        };
      }
    }
  }

  # shred
  if ( $basename eq 'shred' ) {
    return {
      rule     => 'DangerousFilesystem',
      severity => 'medium',
      message  => "shred used to securely delete files",
      command  => $name,
      argv     => $argv,
    };
  }

  # mount / umount
  if ( $basename eq 'mount' || $basename eq 'umount' ) {
    return {
      rule     => 'DangerousFilesystem',
      severity => 'medium',
      message  => "Mount-table manipulation: $basename",
      command  => $name,
      argv     => $argv,
    };
  }

  # losetup / cryptsetup
  if ( $basename eq 'losetup' || $basename eq 'cryptsetup' ) {
    return {
      rule     => 'DangerousFilesystem',
      severity => 'medium',
      message  => "Loop / crypto device manipulation: $basename",
      command  => $name,
      argv     => $argv,
    };
  }

  return;
}

1;
