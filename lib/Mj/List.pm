=head1 NAME

Mj::List.pm - Majordomo list object

=head1 SYNOPSIS

  $list = new Mj::List;
  $list->add('force', "nobody@nowhere.com");

=head1 DESCRIPTION

This contains code for the List object, which encapsulates all per-list
functionality for Majordomo.

A list owns a Config object to maintain configuration data, a
SubscriberList object to store the list of subscribers and their data,
auxiliary SubscriberLists, an Archive object, and a Digest object
handling all archiving and digesting aspects of the list.

=cut

package Mj::List;

use strict;
use Safe;  # For evaluating the address transforms
use Mj::File;
use Mj::FileRepl;
use Mj::SubscriberList;
# use Mj::AddressList;
use Mj::Config qw(parse_table);
use Mj::Addr;
use Mj::Log;
use vars (qw($addr %flags %noflags %classes %digest_types));

# Flags -> [realflag, inverted (2=umbrella), invertible, flag]
%flags = 
  (
   'ackall'       => ['ackall',       2,0,'A'],
   'ackimportant' => ['ackall',       2,0,'a'],
   'ackdeny'      => ['ackall',       0,1,'d'],
   'ackpost'      => ['ackall',       0,1,'f'],
   'ackreject'    => ['ackall',       0,1,'j'],
   'ackstall'     => ['ackall',       0,1,'b'],
   'noack'        => ['ackall',       1,0,'' ],
   'selfcopy'     => ['selfcopy',     0,1,'S'],
   'hideall'      => ['hideall',      0,0,'H'],
   'hideaddress'  => ['hideall',      0,0,'h'],
   'nohide'       => ['hideall',      1,0,'' ],
   'showall'      => ['hideall',      1,0,'' ],
   'eliminatecc'  => ['eliminatecc',  0,1,'C'],
   'prefix'       => ['prefix',       0,1,'P'],
   'replyto'      => ['replyto',      0,1,'R'],
   'rewritefrom'  => ['rewritefrom',  0,1,'W'],
  );

# Special inverse descriptions
%noflags =
  (
   'nohide'  => 'H',
  );


# Classes -> [realclass, takesargs, description]
%classes =
  (
   'each'     => ['each',   0, "each message as it is posted"],
   'single'   => ['each',   0],
   'all'      => ['all',    0, "all list traffic"],
   'digest'   => ['digest', 2, "messages in a digest"],
   'nomail'   => ['nomail', 1, "no messages"],
   'vacation' => ['nomail', 1],
  );

%digest_types =
  (
   'mime'  => 1,
   'index' => 1,
   'text'  => 1,
  );

=head2 new(name, separate_list_dirs)

Creates a list object.  This doesn't check validity or load any config
files (though the later is because the config files load themselves
lazily).  Note that this doesn't create a list; it just creates the object
that is used to hold information about an existing list.

=cut
sub new {
  my $type  = shift;
  my %args  = @_;

  my $class = ref($type) || $type;
  my $log   = new Log::In 150, "$args{'dir'}, $args{'name'}, $args{'backend'}";

  my ($subfile);

  my $self = {};
  bless $self, $class;

  $self->{auxlists} = {};
  $self->{backend}  = $args{backend};
  $self->{callbacks}= $args{callbacks};
  $self->{ldir}     = $args{dir};
  $self->{name}     = $args{name};
  $self->{sdirs}    = 1; # Obsolete goody

  return unless -d "$self->{ldir}/$self->{name}";

  $subfile = $self->_file_path("_subscribers");

  # XXX This should probably be delayed
  unless ($args{name} eq 'GLOBAL' or $args{name} eq 'DEFAULT') {
    $self->{subs} = new Mj::SubscriberList $subfile, $args{'backend'};
  }

  $self->{'config'} = new Mj::Config
    (
     list        => $args{'name'},
     dir         => $args{'dir'},
     callbacks   => $args{'callbacks'},
     defaultdata => $args{'defaultdata'},
    );

  # We have to figure out our database backend for ourselves if we're
  # creating the GLOBAL list, since it couldn't be passed to us.
  if ($args{name} eq 'GLOBAL' or $args{name} eq 'DEFAULT') {
    $self->{backend} = $self->config_get('database_backend');
  }
  $self;
}

=head2 DESTROY (unfinished)

This should close any open thingies and generally make sure we flush
everything, update everything, etc.

=cut
sub DESTROY {
  return 1;
}

=head2 _file_path (private)

This returns the path to the lists'' directory.  If given a name, returns
the full path to that name.  Note that the path returned depends on the
global variable separate_list_dirs.

This is used by the constructor, so it should be before the __END__ token.

=cut
sub _file_path {
  my $self = shift;
  my $file = shift || "";

  if ($self->{'sdirs'}) {
    return "$self->{'ldir'}/$self->{'name'}/$file";
  }
  else {
    return "$self->{'ldir'}/$file";
  }
}

use AutoLoader 'AUTOLOAD';
1;
__END__

#################################

=head1 Subscriber list operations

These functions operate on the subscriber list itself.

=head2 add(mode, address, class, flags)

Adds an address (which must be an Mj::Addr object) to the subscriber list.
The canonical form of the address is used for the database key, and the
other subscriber data is computed and stored in a hash which is passed to
SubscriberList::add.

This passes out the return of SubscriberList::add, which is of the form
(flag, data) where data holds a ref to the subscriber data if there was a
failure due to an existing entry.

=cut
sub add {
  my $self  = shift;
  my $mode  = shift || '';
  my $addr  = shift;
  my $flags = shift || $self->default_flags;
  my $class = shift;
  my $carg  = shift;
  my $carg2 = shift;
  my (@out, $i, $ok, $data);

  $::log->in(120, "$mode, $addr");

  ($class, $carg, $carg2) = $self->default_class
    unless $class;

  $data = {
	   'fulladdr'  => $addr->full,
	   'stripaddr' => $addr->strip,
	   'subtime'   => time,
	   # Changetime handled automatically
	   'class'     => $class,
	   'classarg'  => $carg,
	   'classarg2' => $carg2,
	   'flags'     => $flags,
	  };

  @out = $self->{'subs'}->add($mode, $addr->canon, $data);
  $::log->out;
  @out;
}

=head2 remove(mode, address)

Removes addresses from the main list.  Everything at "add" applies.

=cut
sub remove {
  my $self = shift;
  my $mode = shift;
  my $addr = shift;
  my ($a);

  if ($mode =~ /regex/) {
    $a = $addr;
  }
  else {
    $a = $addr->canon;
  }
  $self->{'subs'}->remove($mode, $a);
}

=head2 is_subscriber(addr)

Returns the subscriber data if the address subscribes to the list.

=cut
sub is_subscriber {
  my $self = shift;
  my $addr = shift;
  my $sublist = shift || '';
  my $log = new Log::In 170, "$self->{'name'}, $addr";
  my ($data, $ok, $out, $subs);

  return unless $addr->isvalid;
  return if $addr->isanon;

  if ($sublist) {
    return $self->aux_is_member($sublist, $addr);
  }

  # If we have cached data within the addr, use it
  $data = $addr->retrieve("$self->{name}-subs");
  return $data if $data;

  # Otherwise see if we have enough cached data to tell us whether they're
  # subscribed or not, so we can save a database lookup
  $subs = $addr->retrieve('subs');
  if ($subs) {
    if ($subs->{$self->{name}}) {
      # We know they're a subscriber, so we can actually look up the data
      $out = $self->{'subs'}->lookup($addr->canon);
      $addr->cache("$self->{name}-subs", $out);
      $log->out('yes-fast');
      return $out;
    }
    else {
      $log->out('no-fast');
      return;
    }
  }

  # We know nothing about the address so we do the lookup
  $out = $self->{'subs'}->lookup($addr->canon);
  if ($out) {
    $addr->cache("$self->{name}-subs", $out);
    $log->out("yes");
    return $out;
  }
  $log->out("no");
  return;
}

=head2 set(addr, setting, check)

This sets various subscriber data.

If $check is true, we check the validity of the settings but don''t
actually change any values.

If $force is true, we don't check to see if the class or flag setting is in
the allowed set.  This is used if the owner is changing normally off-limits
settings.  (XXX Allowed sets not implemented.)

=cut
sub set {
  my $self = shift;
  my $addr = shift;
  my $oset = shift || '';
  my $subl = shift || '';
  my $check= shift;
  my $force= shift;
  my $log  = new Log::In 150, "$addr, $oset";
  my (@allowed, @class, @flags, @settings, $baseflag, $carg1, 
      $carg2, $class, $data, $db, $digest, $flags, $inv, $isflag, 
      $key, $mask, $ok, $rset);

  $oset = lc $oset;
  @settings = split(',', $oset);

  # Loop over settings, checking for legality
  for $set (@settings) {
    ($inv = $set) =~ s/^no//;

    @class = split(/-/, $set);

    if (exists $flags{$set}) {
      $rset = $flags{$set}->[0];
      $isflag = 1;
    }
    elsif (exists $flags{$inv}) {
      $rset = $flags{$inv}->[0];
      $isflag = 1;
    }
    elsif ($rset = $classes{$class[0]}->[0]) {
      $isflag = 0;
    }
    else {
      $log->out("failed, invalid action");
      return (0, "Invalid setting: $set.\n"); # XLANG
    }

    unless ($force) {
      # Check the setting against the allowed flag mask.
      if ($isflag) {
	$mask = $self->config_get('allowed_flags');
        $baseflag = $flags{$rset}->[3];
	# Make sure base flag is in the set.
        unless ($mask =~ /$baseflag/) {
          @allowed = ();
          for (keys %flags) {
            $baseflag = $flags{$flags{$_}->[0]}->[3];
            if ($mask =~ /$baseflag/) {
              push @allowed, $_;
              push @allowed, "no$_" if ($flags{$_}->[2]);
            }
          }
          $baseflag = join "\n               ", @allowed;
          return (0, "Unauthorized flag: $set\nAllowed flags: $baseflag\n");
        }
      }

      # Else it's a class
      else {
	@allowed = keys %{$self->config_get('allowed_classes')};
	# Make sure that one of the allowed classes is at the beginning of
	# the given class.
        unless (grep {$_ eq $rset} @allowed) {
          $data = join " ", @allowed;
          return (0, "Unauthorized class: $set\nAllowed classes: $data\n");
        }
      }
    }
  }

  # Grab subscriber data
  if ($subl eq '') {
    $db = $self->{'subs'};
    ($key, $data) = $self->get_member($addr);
    unless ($data) {
      $log->out("failed, nonmember");
      # XLANG
      return (0, "$addr is not subscribed to the $self->{'name'} list.\n"); 
    }
  }
  else {
    return (0, "Unknown auxiliary list name \"$subl\".") 
      unless $self->valid_aux($subl);
    $self->_make_aux($subl);
    $key  = $addr->canon;
    $db   = $self->{'auxlists'}{$subl};
    $data = $db->lookup($key);
    
    unless ($data) {
      $log->out("failed, nonmember");
      # XLANG
      return (0, "$addr is not subscribed to the $self->{'name'}:$subl auxiliary list.\n"); 
    }
  }

  # If we were checking and didn't bail, we're done
  if ($check > 0) {
    return (1, {
                flags => $data->{'flags'},
	        class => [$data->{'class'}, 
                          $data->{'classarg'}, 
                          $data->{'classarg2'}],
	       },
	   );
  }

  $digest = '';
  for $set (@settings) {
    # Call make_setting to get a new flag list and class setting
    ($ok, $flags, $class, $carg1, $carg2) =
      $self->make_setting($set, $data->{'flags'}, $data->{'class'},
			  $data->{'classarg'}, $data->{'classarg2'});
    return ($ok, $flags) unless $ok;
    return (0, "Digest mode is not supported by auxiliary lists.") 
      if ($subl ne '' and $class eq 'digest');

    # Issue partial digest if changing from 'digest' to 'each'
    if ($data->{'class'} eq 'digest' and $class eq 'each') {
      $ok = $self->digest_examine($data->{'classarg'});
      if ($ok) {
          $digest = $ok->{$data->{'classarg'}};
          $digest->{'type'} = $data->{'classarg2'};
      }
    }
      
    ($data->{'flags'}, $data->{'class'},
     $data->{'classarg'}, $data->{'classarg2'}) =
       ($flags, $class, $carg1, $carg2);
  }

  $db->replace("", $key, $data);
  return (1, {flags  => $flags,
	      class  => [$class, $carg1, $carg2],
              digest => $digest,
	     },
	 );
}

=head2 make_setting

This takes a string and a flag list and class info and returns a class,
class arguments, and a new flag list which reflect the information present
in the string.

=cut
sub make_setting {
  my($self, $str, $flags, $class, $carg1, $carg2) = @_;
  $flags ||= '';
  my $log   = new Log::In 150, "$str, $flags";
  my($arg, $dig, $i, $inv, $isflag, $rset, $set, $time, $type);

  # Split the string on commas; discard empties.  XXX This should probably
  # ignore commas within parentheses.
  for $i (split (/\s*,\s*/, $str)) {
    next unless $i;

    # Deal with digest-(arg with spaces)
    if ($i =~ /(\S+?)\-\((.*)\)/) {
      $set = $1;
      $arg = $2;
    }
    elsif ($i =~ /(\S+?)-(\S+)/) {
      $set = $1;
      $arg = $2;
    }
    else {
      $set = $i;
      $arg = "";
    }

    ($inv = $set) =~ s/^no//;

    if (exists $flags{$set}) {
      $rset = $flags{$set}->[0];
      $isflag = 1;
    }
    elsif (exists $flags{$inv}) {
      $rset = $flags{$inv}->[0];
      $isflag = 1;
    }
    elsif ($rset = $classes{$set}->[0]) {
      $isflag = 0;
    }
    else {
      $log->out("failed, invalidaction");
      return (0, "Invalid setting: $set.\n"); # XLANG
    }

    if ($isflag) {
      # Process flag setting; remove the flag from the list
      if (exists $flags{$inv} and $flags{$inv}->[1] == 0) {
        # Ordinary flags are treated individually.
        $flags =~ s/$flags{$inv}->[3]//ig;
      }
      else {
        # Remove all in group ('noack' and 'ackall' clear all ack flags)
        for (keys %flags) {
          if ($flags{$_}->[0] eq $flags{$rset}->[0] and $flags{$_}->[3]) {
            $flags =~ s/$flags{$_}->[3]//ig; 
          }
        } 
      }
      # Add the new flag (which may be null)
      if (exists $flags{$set}) {
        if ($flags{$set}->[1] == 2) {
          # umbrella (ackall: set all ack flags in the ack group)
          for (keys %flags) {
            if ($flags{$_}->[0] eq $flags{$rset}->[0] 
                and $flags{$_}->[1] == 0) {
              $flags .= $flags{$_}->[3]; 
            }
          } 
        }
        else {
          $flags .= $flags{$set}->[3];
        }
      }
    }
    else {
      # Process class setting

      # Just a plain class
      if ($classes{$rset}->[1] == 0) {
	$class = $rset;
	$carg1 = $carg2 = '';
      }

      # A class taking a time (nomail/vacation)
      elsif ($classes{$rset}->[1] == 1) {
	# If passed 'return', immediately set things back to the saved
	# settings if there were any
	if ($arg eq 'return') {
	  return (0, "Not currently in nomail mode.\n")
	    unless $classes{$class}->[0] eq 'nomail';
	  return (0, "No saved settings to return to.\n")
	    unless $carg2;

	  ($class, $carg1, $carg2) = split("\002", $carg2);
	  $class = 'each' unless defined($class) && $classes{$class};
	  $carg1 = ''     unless defined($carg1);
	  $carg2 = ''     unless defined($carg2);
	}

	# Convert arg to time;
	else {
	  # Eliminate recursive stacking if a user already on 
	  # vacation sets vacation again; just update the time and
	  # don't save away the class info.
	  if ($classes{$class}->[0] ne 'nomail') {
            # Save the old class info
	    $carg2 = join("\002", $class, $carg1, $carg2); 
	  }
          if ($arg) {
            $carg1 = _str_to_time($arg);
            return (0, "Invalid time $arg.\n") unless $carg1; # XLANG
          }
          else {
            $carg1 = '';
          }
	  $class = $rset;
	}
      }

      # Digest mode
      elsif ($rset eq 'digest') {
	# Process the digest data and pick apart the class
	$dig = $self->config_get('digests');
        return (0, "No digests have been configured for the $self->{'name'} list.\n")
          unless exists $dig->{'default_digest'};
	if ($arg) {
	  # The argument may be a digest type
	  if ($digest_types{$arg}) {
	    $type = $arg;
	    $arg = $dig->{'default_digest'};
	  }
	  # Or it mught be a digest name
	  elsif ($dig->{$arg}) {
	    $type = $dig->{$arg}{'type'};
	  }
	  # Or it might be a name-type string
	  elsif ($arg =~ /(.*)-(.*)/) {
	    $arg = $1;
	    $type = $2;
	  }
	  return (0, "Illegal digest name: $arg.\n") # XLANG
	    unless $dig->{lc $arg};
	  return (0, "Illegal digest type: $type.\n") #XLANG
	    unless $digest_types{lc $type};
	}
	else {
	  $arg  = $dig->{'default_digest'};
	  $type = $dig->{$arg}{'type'} || 'mime';
	}
	$class = "digest";
	$carg1 = lc $arg;
	$carg2 = lc $type;
      }
    }
  }
  return (1, $flags, $class, $carg1, $carg2);
}

=head2 _digest_classes

This returns a list of all full digest classes

=cut
sub _digest_classes {
  my $self = shift;
  my ($digests, $i, $j, @out);

  $digests = $self->config_get('digests');
  return unless (ref $digests eq 'HASH');

  for $i (keys %$digests) {
    for $j (keys %digest_types) {
      push @out, "digest-$i-$j";
    }
  }
  @out;
}

=head2 should_ack (sublist, victim, flag)

Determine whether or not a particular action (deny, stall, succeed, reject)
should cause an acknowledgement to be sent to the victim.

=cut
sub should_ack {
  my ($self, $sublist, $victim, $flag) = @_;
  my ($data);

  if ($sublist) {
    $data = $self->aux_get_member($sublist, $victim);
  }
  else {
    $data = $self->get_member($victim);
  }
  unless (defined $data) {
    $data = {};
    $data->{'flags'} = $self->config_get('nonmember_flags');
  }
  # Ack if the victim has the (deprecated) 'ackall' or 'ackimportant' setting.
  return 1 if ($data->{'flags'} =~ /A/i);
  # Ack if victim has requested the flag explicitly.
  return 1 if ($data->{'flags'} =~ /$flag/);
  0;
}


=head2 _str_to_time(string)

This converts a string to a number of seconds since 1970 began.

=cut
sub _str_to_time {
  my $arg = shift;
  my $log = new Log::In 150, $arg;
  my ($time) = 0;

  # Treat a plain number as a count of seconds.
  if ($arg =~ /^(\d+)$/) {
    return time + $arg;
  }

  if ($arg =~ /(\d+)h(ours?)?/) {
    $time += (3600 * $1);
  }
  if ($arg =~ /(\d+)d(ays?)?/) {
    $time += (86400 * $1);
  }
  if ($arg =~ /(\d+)w(eeks?)?/) {
    $time += (86400 * 7 * $1);
  }
  if ($arg =~ /(\d+)m(onths?)?/) {
    $time += (86400 * 30 * $1);
  }
  if ($time) {
    $time += time;
  }
  else {
    # We try calling Date::Manip::ParseDate
    $time = _str_to_time_dm($arg);
  }
  $time;
}

=head2 _str_to_time_dm(string)

Calls Date::Manip to convert a string to a time; this is in a separate
function because it takes forever to load up Date::Manip.  Autoloading is
good.

=cut
use Date::Manip;
sub _str_to_time_dm {
  my $arg = shift;
  $Date::Manip::PersonalCnf="";
  return UnixDate(ParseDate($arg),"%s");
}

=head2 _time_to_str(time)

Converts a time in seconds to an abbreviation. 
For example, a time of 90000 seconds
would produce a string "1d1h" (for one day, one hour).

=cut
sub _time_to_str {
  my $arg = shift;
  my $long = shift || 0;
  return $long ? "0 hours" : "0h" unless ($arg and $arg > 0);
  my ($i, $out);
  $out = '';

  $i = int($arg / (7 * 86400));
  $arg %= (7 * 86400);
  $out .= $long ? ($i > 1)? "$i weeks " : "1 week " : "${i}w" if $i;
  $i = int($arg / 86400);
  $arg %= (86400);
  $out .= $long ? ($i > 1)? "$i days " : "1 day " : "${i}d" if $i;
  $i = int(($arg + 1800) / 3600);
  $arg %= (3600);
  $out .= $long ? ($i > 1)? "$i hours" : "1 hour" : "${i}h" if $i;
  unless ($out) {
    if ($long) {
      $i = int(($arg + 30) / 60);
      $out = ($i > 1)? "$i minutes" : "1 minute";
    }
    else {
      $out = "0h";
    }
  }
   
  $out;
}

=head2 default_class

This returns the default subscription class for new subscribers.

This should be a per-list variable.

=cut
sub default_class {
  my $self = shift;
  my $class = $self->config_get('default_class');

  ($ok, undef, $class, $carg1, $carg2) = $self->make_setting($class);
  return ($class, $carg1, $carg2) if $ok;
  return ('each', '', '');
}

=head2 default_flags

This returns the default flags (as a string) for new subscribers.

This should be a per-list variable, or a whole set of list variables.

=cut
sub default_flags {
  my $self = shift;
  return $self->config_get('default_flags');
}

=head2 flag_set(flag, address)

Returns true if the address is a subscriber and has the given flag set.
Don''t ask for flags in the off state (noprefix, etc.) because this will
not provide a useful result.

This stashes the flags within the address so that repeated lookups will be
cheap.

=cut
sub flag_set {
  my $self = shift;
  my $flag = shift;
  my $addr = shift;
  my $force= shift;
  my $log  = new Log::In 150, "$flag, $addr";
  $log->out('no');
  my ($flags, $data);
  return unless $flags{$flag};
  return unless $addr->isvalid;

  $flags = $addr->retrieve("$self->{name}-flags");

  if ($force || !defined($flags)) {
    $data = $self->is_subscriber($addr);
    if ($data) {
      $flags = $data->{flags};
    }
    else {
      $flags = $self->config_get('nonmember_flags');
    }
    $addr->cache("$self->{name}-flags", $flags);
  }

  return unless $flags =~ /$flags{$flag}[3]/;
  $log->out('yes');
  1;
}

=head2 describe_flags(flag_string)

This returns a list of strings which give the names of the flags set in
flag_string.

=cut
sub describe_flags {
  my $self    = shift;
  my $flags   = shift || "";
  my $setting = shift;
  my %nodesc  = reverse %noflags;
  my (%desc, @out, $i, $seen);

  for $i (keys %flags) {
    $desc{$flags{$i}->[3]} = $i if $flags{$i}->[3];
  }

  $seen = "";
  for $i (sort keys %desc) {
    if ($flags =~ /$i/) {
      push @out, $desc{$i};
      $seen .= $i;
    }
    else {
      unless ($flags{$desc{$i}}->[1] == 2 || $seen =~ /$i/i || $flags =~ /$i/i) {
	push @out, $nodesc{$i} || "no$desc{$i}"; # XLANG
	$seen .= $i;
      }
    }
  }
  @out;
}

=head2 describe_class(class)

This returns a textual description for a subscriber class.

If as_setting is true, the description returned is in the form taken by the
set command.

=cut
sub describe_class {
  my $self  = shift;
  my $class = shift;
  my $arg1  = shift;
  my $arg2  = shift;
  my $as_setting = shift;
  my($dig, $time, $type);

  if ($class eq 'digest') {
    $dig = $self->config_get('digests');
    if ($dig->{$arg1}) {
      return $as_setting? "$class-$arg1-$arg2" :
	$dig->{$arg1}{'desc'};
    }
    else {
      return "Undefined digest." # XLANG
    }
  }

  if ($classes{$class}->[1] == 0) {
    return $as_setting? $class : $classes{$class}->[2];
  }
  if ($classes{$class}->[1] == 1) {
    # nomail setting
    if ($arg1) {
      if ($as_setting) {
        return sprintf "$class-%s", _time_to_str($arg1 - time);
      }
      else { 
        $time = gmtime($arg1);
        return "$classes{$class}->[2] until $time"; # XLANG
      }
    }
    return $classes{$class}->[2];
  }
  return $classes{$class}->[2];
}

=head2 get_start()

Begin iterating over the list of subscribers.

=cut
sub get_start {
  shift->{'subs'}->get_start;
}

=head2 get_chunk(max_size)

Returns an array of subscriber data hashrefs of a certain maximum size.

=cut
sub get_chunk {
  my $self = shift;
  my (@addrs, @out, $i);

  @addrs = $self->{'subs'}->get(@_);
  while ((undef, $i) = splice(@addrs, 0, 2)) {
    push @out, $i;
  }
  return @out;
}

=head2 get_matching_chunk(max_size, field, value)

Returns an array of (key, hashref) pairs of max_size size of subscribers
(and data) with data field $field eq $value.

=cut
sub get_matching_chunk {
  my $self = shift;
  $self->{'subs'}->get_matching(@_);
}

=head2 get_done()

Closes the iterator.

=cut
sub get_done {
  shift->{'subs'}->get_done;
}

=head2 search(string, mode)

This searches the full addresses for a match to a string or regexp.  The
iterator must be opened before doing this.

Regexp matching is done sensitive to case.  This is Perl5; if you don''t want
that, use (?i).

This returns a list of (key, data) pairs.

=cut
sub search {
  my $self   = shift;
  my $string = shift;
  my $mode   = shift;

  if ($mode =~ /regexp/) {
    return ($self->{'subs'}->get_matching_regexp(1, 'fulladdr', $string))[0];
  }
  return ($self->{'subs'}->get_matching_regexp(1, 'fulladdr', "\Q$string\E"))[0];
}

=head2 get_member(address)

This takes an address and returns the member data for that address, or
undef if the address is not a member.

This will reset the list iterator.

=cut
sub get_member {
  my $self = shift;
  my $addr = shift;
  
  return ($addr->canon, $self->{'subs'}->lookup($addr->canon));
}

=head2 count_subs {

  Counts the number of entries in a subscriber database.

=cut
sub count_subs {
  my $self = shift;
  my $sublist = shift;
  my (@count, $db);
  my ($total) = 0;
 
  if ($sublist) {
    return unless $self->_make_aux($sublist);
    $db = $self->{'auxlists'}{$sublist}; 
  }
  else {
    $db = $self->{'subs'};
  }
   
  return unless $db->get_start;
  while (@count = $db->get_quick(1000)) {
    $total += scalar @count;
  }
  $db->get_done;
  $total;
}


=head2 rekey()

This regenerates the keys for the databases from the stripped addresses in
the event that the transformation rules change.

=cut
sub rekey {
  my $self = shift;
  $self->subscriber_rekey 
    unless ($self->{name} eq 'GLOBAL' or $self->{name} eq 'DEFAULT');
  $self->aux_rekey_all;
}

sub subscriber_rekey {
  my $self = shift;
  my $sub =
    sub {
      my $key  = shift;
      my $data = shift;
      my (@out, $addr, $newkey, $changekey);

      # Allocate an Mj::Addr object from stripaddr and transform it.  XXX
      # Why not canon instead?
      $addr = new Mj::Addr($data->{'stripaddr'});
      $newkey = $addr->xform;
      $changekey = ($newkey ne $key);
      
      return ($changekey, 0, $newkey);
    };
  $self->{'subs'}->mogrify($sub);
}

######################

=head1 Auxiliary AddressList functions

Thses operate on additional lists of addresses (implemented via the
AddressList object) which are associated with the main list.  These list
are intended to duplicate the function of the old restrict_post files, and
be remotely modifiable, to boot.  They can be used to contain any list of
addresses for any purpose, such as lists of banned addresses or what have
you.  The extended access mechanism is expected to make extensive use of
these.

=head2 aux_add(file, mode, address)

=cut
sub aux_add {
  my $self = shift;
  my $name = shift;
  my $mode = shift || '';
  my $addr = shift;
  my ($ok, $caddr, $data);

  $data  =
    {
     'fulladdr'  => $addr->full,
     'stripaddr' => $addr->strip,
     'subtime'   => time,
     # Changetime handled automatically
     'class'     => 'each',
     'classarg'  => '',
     'classarg2' => '',
     'flags'     => $self->default_flags,
    };

  $self->_make_aux($name);
  ($ok, $data) = $self->{'auxlists'}{$name}->add($mode, $addr->canon, $data);
  unless ($ok) {
    return (0, "Address is already a member of $name as $data->{'stripaddr'}.\n"); # XLANG
  }
  return 1;
}

=head2 aux_remove(file, mode, address_list)

Remove addresses from an auxiliary list.

=cut
sub aux_remove {
  my $self = shift;
  my $name = shift;
  my $mode = shift;
  my $addr = shift;
  my $log = new Log::In 150, "$name, $mode, $addr";
  my ($ok);

  unless ($mode =~ /regex/) {
    $addr = $addr->canon;
  }

  $self->_make_aux($name);
  $self->{'auxlists'}{$name}->remove($mode, $addr);
}

=head2 aux_get_start(file)

Begin iterating over the members of an auxiliary list.

=cut
sub aux_get_start {
  my $self = shift;
  my $name = shift;
  
  $self->_make_aux($name);
  $self->{'auxlists'}{$name}->get_start;
}

=head2 aux_get_chunk(file, max_size)

Returns an array of members of an auxiliary list of a certain maximum size.

=cut
sub aux_get_chunk {
  my $self = shift;
  my $name = shift;
  my $size = shift;
  my (@addrs, @out, $i);
  
  $self->_make_aux($name);
  @addrs = $self->{'auxlists'}{$name}->get($size);
  while ((undef, $i) = splice(@addrs, 0, 2)) {
    push @out, $i;
  }
  return @out;
}

=head2 aux_get_done(file)

Stop iterating over the members of an auxiliary list.

=cut
sub aux_get_done {
  my $self = shift;
  my $name = shift;
  my $log  = new Log::In 150, $name;

  $self->_make_aux($name);
  $self->{'auxlists'}{$name}->get_done;
}

=head2 aux_get_matching

Return a block of data.  The size of the block and the
conditions for matching are determined by the arguments.

=cut
sub aux_get_matching {
  my $self = shift;
  my $name = shift;

  $self->_make_aux($name);
  $self->{'auxlists'}{$name}->get_matching(@_);
}

=head2 aux_get_member(sublist, address)

Returns the unstringified data for a particular sublist member

=cut
sub aux_get_member {
  my $self = shift;
  my $name = shift;
  my $addr = shift;
  my ($saddr, $ok);

  return unless $addr->isvalid;
  return if $addr->isanon;

  return unless $self->_make_aux($name);
  return $self->{'auxlists'}{$name}->lookup($addr->canon);
}

=head2 aux_is_member(file, addr)

This returns true if an address is a member of an auxiliary list.

=cut
sub aux_is_member {
  my $self = shift;
  my $name = shift;
  my $addr = shift;
  my ($saddr, $ok);

  return 0 unless $addr->isvalid;
  return 0 if $addr->isanon;

  $self->_make_aux($name);
  return $self->{'auxlists'}{$name}->lookup_quick($addr->canon);
}

=head2 aux_rekey_all()

This rekeys all auxiliary lists associated with a list.

=cut
sub aux_rekey_all {
  my $self = shift;
  my $i;

  $self->_fill_aux;
  for $i (keys %{$self->{'auxlists'}}) {
    $self->aux_rekey($i);
  }
}

=head2 aux_rekey(name)

This rekeys a single auxiliary file.

=cut
sub aux_rekey {
  my $self = shift;
  my $name = shift;

  my $sub =
    sub {
      my $key  = shift;
      my $data = shift;
      my (@out, $addr, $newkey, $changekey);

      # Allocate an Mj::Addr object from stripaddr and transform it.  XXX
      # Why not canon instead?
      $addr = new Mj::Addr($data->{'stripaddr'});
      $newkey = $addr->xform;
      $changekey = ($newkey ne $key or (! exists $data->{'class'}));

      # Enable transition from old AddressList to new SubscriberList
      $data->{'subtime'}  ||= $data->{'changetime'};
      $data->{'fulladdr'} ||= $data->{'stripaddr'};
      $data->{'class'}    ||= 'each';
      $data->{'flags'}    ||= $self->default_flags;
      
      return ($changekey, $data, $newkey);
    };

  $self->_make_aux($name);
  $self->{'auxlists'}{$name}->mogrify($sub);
}


=head2 _fill_aux

This fills in the hash of auxiliary lists associated with a List object.
Only preexisting lists are accounted for; others can be created at any
time.  This does not actually create the objects, only the hash slots, so
that they can be tested for with exists().

=cut
sub _fill_aux {
  my $self = shift;

  # Bail early if we don't have to do anything
  return 1 if $self->{'aux_loaded'};
  
  $::log->in(120);

  my $dirh = new IO::Handle;
  my ($file);
  
  my $listdir = $self->_file_path;
  opendir($dirh, $listdir) || $::log->abort("Error opening $listdir: $!");

  while (defined($file = readdir $dirh)) {
    if ($file =~ /^X(.*)\..*/) {
      $self->{'auxlists'}{$1} = undef;
    }
  }
  closedir($dirh);
  
  $self->{'aux_loaded'} = 1;
  $::log->out;
  1;
}

=head2 moderators($group)

Returns an array of addresses corresponding to the list moderators.
In decreasing order, the sources are:
  The "moderators" or another, named auxiliary list.
  The "moderators" configuration setting.
  The "moderator" configuration setting.
  The "sender" configuration setting.

=cut

sub moderators {
  my $self = shift;
  my $group = shift;
  my (@addr, @out, $i);

  $self->_fill_aux;
  unless (defined $group and exists $self->{'auxlists'}{$group}) {
    $group = 'moderators';
  }
  if (exists $self->{'auxlists'}{$group}) {
    return unless $self->aux_get_start($group);
    while (@addr = $self->aux_get_chunk($group, 4)) {
      for $i (@addr) {
        push @out, $i->{'stripaddr'} if ($i->{'class'} ne 'nomail');
      }
    }
    return @out if (scalar @out);
  }
  @out = @{$self->config_get('moderators')};
  return @out if (scalar @out);
  $self->config_get('moderator') || $self->config_get('sender');
}
 
  

=head1 FileSpace interface functions

These provide an interface into the list''s FileSpace object.

=cut
use Mj::FileSpace;
sub fs_get {
  my $self  = shift;
  $self->_make_fs || return;
  $self->{'fs'}->get(@_);
}

use Mj::FileSpace;
sub fs_put {
  my $self = shift;
  $self->_make_fs || return;
  $self->{'fs'}->put(@_);
}

use Mj::FileSpace;
sub fs_put_start {
  my $self = shift;
  $self->_make_fs || return;
  $self->{'fs'}->put_start(@_);
}

use Mj::FileSpace;
sub fs_put_chunk {
  my $self = shift;
  $self->_make_fs || return;
  $self->{'fs'}->put_chunk(@_);
}

use Mj::FileSpace;
sub fs_put_done {
  my $self = shift;
  $self->_make_fs || return;
  $self->{'fs'}->put_done(@_);
}

use Mj::FileSpace;
sub fs_delete {
  my $self = shift;
  my $log = new Log::In 150, $_[0];
  $self->_make_fs || return;
  $self->{'fs'}->delete(@_);
}

use Mj::FileSpace;
sub fs_index {
  my $self = shift;
  $self->_make_fs || return;
  $self->{'fs'}->index(@_);
}

use Mj::FileSpace;
sub fs_mkdir {
  my $self = shift;
  $self->_make_fs || return;
  $self->{'fs'}->mkdir(@_);
}

=head1 Message ID/Checksum database management functions

These routines handle querying and adding records to the lists of message
ids checksums that a list maintains in order to keep track of duplicates.

=head2 check_dup(rec, type)

Checks to see if rec exists in the duplicate database _dup_type.

Returns truth if so.  Adds the record to the database in any case.

=cut
sub check_dup {
  my $self = shift;
  my $rec  = shift; # ID or checksum to check
  my $type = shift; # "id", "sum" or "partial"
  my $log  = new Log::In 150, $rec;
  my ($data, $ok);

  $self->_make_dup($type);
  ($rec) = $rec =~ /(.*)/; # Untaint
  ($ok, $data) = $self->{'dup'}{$type}->add("", $rec, {});

  # Inverted logic here; we return nothing only if we didn't get a match
  return $data;
}

=head2 remove_dup(rec, type)

Removes the record of a duplicate from a duplicate database.

=cut
sub remove_dup {
  my $self = shift;
  my $rec  = shift; # ID or checksum to check
  my $type = shift; # "id", "sum" or "partial"
  my $log  = new Log::In 150, $rec;
  my ($data, $ok);

  $self->_make_dup($type);
  ($rec) = $rec =~ /(.*)/; # Untaint
  ($ok, $data) = $self->{'dup'}{$type}->remove("", $rec);

  return $ok;
}

=head2 expire_dup

This removes old entries from the three duplicate databases.

=cut
sub expire_dup {
  my $self = shift;
  my $time = time;
  my $days = $self->config_get('dup_lifetime');
  my (@nuked, $i);

  my $mogrify = sub {
    my $key  = shift;
    my $data = shift;

    if ($data->{'changetime'} + $days*86400 < $time) {
      push @nuked, $key;
      return (1, 1, undef);
    }
    return (0, 0);
  };

  # Kill old entries from the various dup databases.
  for $i ('id', 'sum', 'partial') {
    $self->_make_dup($i);
    $self->{'dup'}{$i}->mogrify($mogrify);
  }

  return @nuked
}

=head2 post_add

Add a post event to the post database, and return the parsed
data.

=cut
use Mj::AddressList;
sub post_add {
  my($self, $addr, $time, $type, $number) = @_;
  my $log = new Log::In 150, "$time #$number";
  my($data, $event, $ok);

  unless (exists $self->{'posts'}) {
    $self->{'posts'} = new Mj::AddressList $self->_file_path("_posts"), 
                                           $self->{'backend'};
  }

  return unless $self->{'posts'};
    
  $event = "$time$type$number";
  $data = $self->{'posts'}->lookup($addr->canon);
  if ($data) {
    $data->{'comment'} .= " $event";
    $self->{'posts'}->replace('', $addr->canon, $data);
  }
  else {
    $data = {};
    $data->{'comment'} = $event;
    $self->{'posts'}->add('', $addr->canon, $data);
  }
}

=head2 get_post_data

This converts members with timed nomail classes back to their old class
when the vacation time is passed and removes old bounce data.

=cut
use Mj::AddressList;
sub get_post_data {
  my $self = shift;
  my $addr = shift;
  my (@msgs);

  unless (exists $self->{'posts'}) {
    $self->{'posts'} = new Mj::AddressList $self->_file_path("_posts"), 
                                           $self->{'backend'};
  }

  return unless $self->{'posts'};
  my $data = $self->{'posts'}->lookup($addr->canon);
  if ($data) {
    @msgs = split ' ', $data->{'comment'};
    $data = {};
    for (@msgs) {
      if ($_ =~ /(\d+)\w(\d+)/) {
        $data->{$2} = $1;
      }
    }
  }
  $data;
}

=head2 expire_post_data

This expires old data about posted messages.

=cut
use Mj::AddressList;
sub expire_post_data {
  my $self = shift;
  # XXX Use twice the lifetime of duplicates.
  my $expiretime = time - $self->config_get('dup_lifetime') * 2*60*60*24;

  unless (exists $self->{'posts'}) {
    $self->{'posts'} = new Mj::AddressList $self->_file_path("_posts"), 
                                           $self->{'backend'};
  }

  return unless $self->{'posts'};

  my $mogrify = sub {
    my $key  = shift;
    my $data = shift;
    my (@b1, @b2, $b, $t);

    # Fast exit if we have no expired timers and no bounce data
    return (0, 0) if !$data->{comment};

    # Expire old posted message data.
    @b1 = split(/\s+/, $data->{comment});
    while (1) {
      $b = pop @b1; last unless defined $b;
      ($t) = $b =~ /^(\d+)\w/;
      next if $t < $expiretime;
      push @b2, $b; 
    }
    $data->{comment} = join(' ', @b2);

    # Update if necessary
    if (@b2) {
      return (0, 1, $data);
    }
    return (0, 0);
  };

  $self->{'posts'}->mogrify($mogrify);
}

=head2 expire_subscriber_data

This converts members with timed nomail classes back to their old class
when the vacation time is passed and removes old bounce data.

=cut
sub expire_subscriber_data {
  my $self = shift;
  my $time = time;
  my $maxbouncecount = $self->config_get('bounce_max_count');
  my $maxbounceage   = $self->config_get('bounce_max_age') * 60*60*24;
  my $bounceexpiretime = $time - $maxbounceage;
  my $ali;

  my $mogrify = sub {
    my $key  = shift;
    my $data = shift;
    my (@b1, @b2, $a1, $a2, $b, $c, $e, $u1, $u2, $t);

    # True if we have an expired timer
    $e = ($data->{class} eq 'nomail' &&
	  $data->{classarg}          &&
	  $time > $data->{classarg}
	 );

    # Fast exit if we have no expired timers and no bounce data
    return (0, 0) if !$e && !$data->{bounce};
    if ($e) {
      # Now we know we must expire; extract the args
      ($c, $a1, $a2) = split("\002", $data->{classarg2});
      $data->{'class'}     = defined $c  ? $c  : 'each';
      $data->{'classarg'}  = defined $a1 ? $a1 : '';
      $data->{'classarg2'} = defined $a2 ? $a2 : '';
      $u1 = 1;
    }

    # Expire old bounce data.
    if ($data->{bounce}) {
      @b1 = split(/\s+/, $data->{bounce});
      $c = 0;
      while (1) {
	last if $c >= $maxbouncecount;
	$b = pop @b1; last unless defined $b;
	($t) = $b =~ /^(\d+)\w/;
	next if $t < $bounceexpiretime;
	push @b2, $b; $c++;
	$u2 = 1;
      }
      $data->{bounce} = join(' ', @b2) if $u2;
    }

    # Update if necessary
    if ($u1 || $u2) {
      return (0, 1, $data);
    }
    return (0, 0);
  };

  # If the list is configured to allow posting to 
  # auxiliary lists, the subscriber data for
  # them must be expired as well.
  $ali = $self->config_get('aliases');
  if ($ali =~ /A/) {
    $self->_fill_aux;
    for (keys %{$self->{'auxlists'}}) {
      $self->_make_aux($_);
      $self->{'auxlists'}{$_}->mogrify($mogrify);
    }
  }     
  $self->{subs}->mogrify($mogrify);
}


=head2 _make_aux (private)

This makes a SubscriberList object and stuff it into the List''s collection.
This must be called before any function which accesses the SubscriberList.

=cut
sub _make_aux {
  my $self = shift;
  my $name = shift;

  unless (defined $self->{'auxlists'}{$name}) {
    $self->{'auxlists'}{$name} =
      new Mj::SubscriberList $self->_file_path("X$name"), $self->{backend};
  }
  1;
}

=head2 valid_aux

Verify the existence of an auxiliary list.  

=cut
sub valid_aux {
  my $self = shift;
  my $name = shift;

  $self->_fill_aux;
  if (exists $self->{'auxlists'}{$name}) {
    # Untaint
    $name =~ /(.*)/; $name = $1;
    return $name;
  }
  return;
}


=head2 _make_fs

Makes a filespace object.

=cut
use Mj::FileSpace;
sub _make_fs {
  my $self = shift;
  return 1 if $self->{'fs'};
  my $dir = $self->{'config'}->get("filedir");
  $dir = $self->_file_path("files") unless $dir;
  $self->{'fs'} = new Mj::FileSpace($dir, $self->{backend});
  return unless $self->{'fs'};
  1;
}

=head2 _make_dup(type)

This makes a very simple database for storing just keys and a time (for
expiry).  This is used to keep track of duplicate checksums and
message-ids.

=cut
use Mj::SimpleDB;
sub _make_dup {
  my $self = shift;
  my $type = shift;
  return 1 if $self->{'dup'}{$type};

  $self->{'dup'}{$type} =
    new Mj::SimpleDB(filename => $self->_file_path("_dup_$type"),
		     backend  => $self->{backend},
		     fields   => ['changetime'],
		    );
  1;
}

=head2 _make_digest

This instantiates the Digest object.

=cut
use Mj::Digest;
sub _make_digest {
  my $self = shift;
  return 1 if $self->{'digest'};
  $self->_make_archive;

  $self->{'digest'} = new Mj::Digest($self->{archive},
				     "$self->{ldir}/$self->{name}",
				     $self->config_get('digests'),
				    );
}

=head2 _make_archive

This instantiates the Archive object.

=cut
use Mj::Archive;
sub _make_archive {
  my $self = shift;
  return 1 if $self->{'archive'};
  my $dir = $self->config_get('archive_dir');

  # Default to /public/archive
  unless ($dir) {
    ($dir) = $self->fs_get('public/archive', 1, 1);
  }

  # Go away if we still don't have anything
  return unless $dir && -d $dir;

  # Create the archive
  $self->{'archive'} = new Mj::Archive ($dir,
					$self->{'name'},
					$self->config_get('archive_split'),
					$self->config_get('archive_size'),
				       );
  1;
}

=head1 Miscellaneous functions

Config modification, access checking, special bootstrapping functions for
the Majordomo object.

=head2 config_get

Retrieves a variable from the list''s Config object.

=cut
sub config_get {
  my $self = shift;
  $self->{'config'}->get(@_);
}

=head2 config_set

Sets a variable in the Config object.

=cut
sub config_set {
  my $self = shift;
  $self->{'config'}->set(@_);
}

=head2 config_set_to_default

Sets a variable to track the default value.

=cut
sub config_set_to_default {
  shift->{'config'}->set_to_default(@_);
}

=head2 config_save

Saves the config files, if necessary.

=cut
sub config_save {
  shift->{'config'}->save;
}

sub config_lock {
  shift->{'config'}->lock;
}

sub config_unlock {
  shift->{'config'}->unlock;
}

sub config_get_allowed {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->allowed($var);
}

sub config_get_comment {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->comment($var);
}

sub config_get_default {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->default($var);
}

sub config_get_intro {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->intro($var);
}

sub config_get_isarray {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->isarray($var);
}

sub config_get_isauto {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->isauto($var);
}

sub config_get_visible {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->visible($var);
}

sub config_get_whence {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->whence($var);
}

sub config_get_mutable {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->mutable($var);
}

sub config_get_groups {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->groups($var);
}

sub config_get_type {
  my $self = shift;
  my $var  = shift;
  $self->{'config'}->type($var);
}

sub config_get_vars {
  my $self = shift;
  $self->{'config'}->vars(@_);
}

=head1 Archive functions

These interface with the list''s Archive object.

=head2 archive_add_start(sender, data), archive_add_done(file)

This adds a message contained in a file to the archive.  _start gives you a
message number, _done actually commits the add.  The archive is
write-locked between calls to these functions, so it is important to
minimise the elapsed time between the two calls.

=cut
sub archive_add_start {
  my $self = shift;
  return unless $self->_make_archive;
  $self->{'archive'}->add_start(@_);
}

sub archive_add_done {
  my $self = shift;
  $self->{'archive'}->add_done(@_);
}

=head2 archive_get_start,chunk,done

Pass through to the archive interface

=cut
sub archive_get_start {
  my $self = shift;
  return unless $self->_make_archive;
  $self->{'archive'}->get_message(@_);
}

sub archive_get_chunk {
  my $self = shift;
  $self->{'archive'}->get_chunk(@_);
}

sub archive_get_done {
  my $self = shift;
  $self->{'archive'}->get_done(@_);
}

sub archive_expand_range {
  my $self = shift;
  return unless $self->_make_archive;
  $self->{'archive'}->expand_range(@_);
}

sub archive_delete_msg {
  my $self = shift;
  return unless $self->_make_archive;
  $self->{'archive'}->remove(@_);
}

sub archive_find {
  my $self = shift;
  my $patt = shift;
  my ($ok, $mess, $regex) = compile_pattern($patt, 0, "exact");
  return ($ok, $mess) unless $ok;
  return unless $self->_make_archive;
  $self->{'archive'}->find($regex);
}

sub archive_sync {
  my $self = shift;
  my $qp = $self->config_get('quote_pattern');
  return unless $self->_make_archive;
  $self->{'archive'}->sync(@_, $qp);
}

sub count_posts {
  my $self = shift;
  my $days = shift;
  my (@msgs) = ();
  return 0 unless (defined $days and $days > 0);
  return 0 unless $self->_make_archive;
  @msgs = $self->{'archive'}->expand_range(0, $days . "d");
  return scalar @msgs;
}


=head1 Digest functions

These functions interface with the list''s Digest object.

=head2 digest_build

Builds a digest.

=cut
use Mj::Digest::Build;
sub digest_build {
  my $self = shift;
  $self->_make_archive;
  Mj::Digest::Build::build(@_, 'archive' => $self->{'archive'});
}

=head2 digest_add

Adds an [article, data] pair to the lists'' digest object.  This will
return what Mj::Digest::add returns, which is a hash keyed on digest name
containing the list of [article, data] pairs of the messages in that digest
which need to be sent out.

=cut
sub digest_add {
  my $self = shift;
  $self->_make_digest;
  $self->{digest}->add(@_);
}

=head2 digest_trigger

Trigger a digest.  This does what digest_add does, but instead of adding a
message it just checks to see if a digest should be sent.  The return is
the same as digest_add.

=cut
sub digest_trigger {
  my $self = shift;
  $self->_make_digest;
  $self->{digest}->trigger(@_);
}

=head2 digest_examine

Examine the current state of the digests without making any changes.

=cut
sub digest_examine {
  my $self = shift;
  if ($self->_make_digest) {
    $self->{digest}->examine(@_);
  }
}

=head2 digest_incvol(inc, digests)

Increment the volume numbers and reset the issue numbers for the given
digests.

$inc is a list of digests to increment the volume numbers of.  All digests
wil have their volume numbers incremented if this is not defined.

$digests is the parsed 'digests' variable; it will be extracted if not
defined.

=cut
sub digest_incvol {
  my $self    = shift;
  my $inc     = shift;
  my $digests = shift;
  my $log = new Log::In 150;
  my (%inc, @tmp, $i, $issues);

  $digests ||= $self->config_get('digests');
  $inc     ||= [keys(%$digests)];

  use Data::Dumper; print Dumper $inc;

  # Build a quick lookup hash
  for $i (@$inc) {
    $inc{$i} = 1;
  }

  $self->config_lock;
  # In critical section

  $issues = $self->config_get('digest_issues');

  # Note that we iterate over all defined digests (and skip the default
  # entry) because we need to rebuild the complete structure, even for the
  # items which aren't changing.
  for $i (keys(%$digests)) {
    next if $i eq 'default_digest';
    $issues->{$i}{volume} ||= 1; $issues->{$i}{issue} ||= 1;
    if ($inc{$i}) {
      # If we're in the set to be changed, up the volume and reset the
      # issue to 1
      push @tmp, "$i : " . ($issues->{$i}{volume}+1) ." : 1";
    }
    else {
      # Else leave it alone completely
      push @tmp, "$i : $issues->{$i}{volume} : $issues->{$i}{issue}";
    }
  }
  $self->config_set('digest_issues', @tmp);

  # Exit critical section
  $self->config_unlock;

  return $issues;
}

=head2 digest_incissue(inc, digests)

Increment the issue numbers for the given digests.

$inc is a listref of digest names which will have their issue numbers
incremented.  $digests is the parsed 'digests' variable; it is looked up if
not provided.

Returns the final 'digest_issues' structure.

=cut
sub digest_incissue {
  my $self    = shift;
  my $inc     = shift;
  my $digests = shift;
  my $log = new Log::In 150;
  my (%inc, @tmp, $i, $issues);

  $digests ||= $self->config_get('digests');

  # Build a quick lookup hash
  for $i (@$inc) {
    $inc{$i} = 1;
  }

  $self->config_lock;
  # In critical section

  $issues = $self->config_get('digest_issues');

  # Note that we iterate over all defined digests (and skip the default
  # entry) because we need to rebuild the complete structure, even for the
  # items which aren't changing.
  for $i (keys(%$digests)) {
    next if $i eq 'default_digest';
    $issues->{$i}{volume} ||= 1; $issues->{$i}{issue} ||= 1;
    push @tmp, "$i : $issues->{$i}{volume} " .
      " : " . ($issues->{$i}{issue}+($inc{$i} ? 1 : 0));
  }
  $self->config_set('digest_issues', @tmp);

  # Exit critical section
  $self->config_unlock;

  return $issues;
}

=head1 Bounce data functions

These involve manipulating per-user bounce data.

=head2 bounce_get

Retrieves the stored bounce data and returns it in parsed format.  Will use
cached data unless $force is true.

=cut
sub bounce_get {
  my $self = shift;
  my $addr = shift;
  my $force= shift;
  my ($data);

  $data = $addr->retrieve("$self->{name}-subs");

  if ($force || !$data) {
    $data = $self->is_subscriber($addr);
  }

  return unless $data && $data->{bounce};
  return $self->_bounce_parse_data($data->{bounce});
}

=head2 bounce_add

Add a bounce event to a user's saved bounce data, and return the parsed
data.

=cut
sub bounce_add {
  my($self, $addr, $time, $type, $number, $diagnostic) = @_;
  my $log = new Log::In 150, "$time T$type #$number";
  my($bouncedata, $event, $ok);

  $event = "$time$type$number";
  my $repl = sub {
    my $data = shift;

    if ($data->{bounce}) {
      $data->{bounce} .= " $event";
    }
    else {
      $data->{bounce} = $event;
    }

    if ($diagnostic) {
      $data->{diagnostic} = substr ($diagnostic, 0, 160);
      $data->{diagnostic} =~ s/\001/X/g;
    }

    $bouncedata = $data->{bounce};
    $data;
  };

  $ok = $self->{subs}->replace('', $addr->canon, $repl);
  return $self->_bounce_parse_data($bouncedata) if $ok;
  return;
}

=head2 _bounce_parse_data

This takes apart a string of bounce data.  The string is simply a set of
space-separated bounce incidents; each incident contains minimal
information about a bounce: the time and the message numbers.  There may
also be other data there depending on what bounces were detected.

An incident is formatted like:

timeMnumber

where 'time' is the numeric cound of seconds since the epoch, 'M' indicates
a message bounce and 'number' indicates the message number.

Some bounces have a type but no message number.  There are stored under
separate hash keys ("U$type") in flat lists.

=cut
sub _bounce_parse_data {
  my $self = shift;
  my $data = shift;
  my (@incidents, $i, $out);

  $out = {};
  @incidents = split(/\s/, $data);

  for $i (@incidents) {
    ($time, $type, $number) = $i =~ /^(\d+)(\w)(.*)$/;
    if ($number) {
      $out->{$type}{$number} = $time;
    }
    else {
      $out->{"U$type"} ||= ();
      push @{$out->{"U$type"}}, $time;
    }
  }

  $out;
}

=head2 bounce_gen_stats

Generate a bunch of statistics from a set of bounce data.

Things generated:

number of bounces in last day
                          week
                          month
number of consecutive bounces
percentage of bounced messages

The first three are generated using only the collected bounce times.  The
last two are generated using bounces for which message numbers were
collected and require a pool of that type bounce (two and five, resp.)
before any statistics are generated.

=cut 
sub bounce_gen_stats {
  my $self = shift;
  my $bdata = shift;
  my $now = time;
  my (@numbered, @times, $maxbounceage, $maxbouncecount, $stats);

  return unless $bdata;

  # We don't do a monthly view unless we're collecting a month's worth of
  # data
  $maxbounceage   = $self->config_get('bounce_max_age');
  $maxbouncecount = $self->config_get('bounce_max_count');
  if ($maxbounceage >= 30) {
    $do_month = 1;
  }

  @numbered = sort {$a <=> $b} keys(%{$bdata->{M}});
  if (@numbered) {
    $stats->{span} = $numbered[$#numbered] - $numbered[0] + 1;
  }
  else {
    $stats->{span} = 0;
  }

  for $i (@numbered) {
    push @times, $bdata->{M}{$i};
    $stats->{numbered}++;
    if (!defined($lastnum) || $i == $lastnum+1) {
      $lastnum = $i;
      $stats->{consecutive}++;
    }
  }

  # We shouldn't export some statistics unless they're relevant
  delete($stats->{consecutive})
    unless $stats->{consecutive} && $stats->{consecutive} >= 2;

  if ($stats->{numbered} && $stats->{numbered} >= 5) {
    $stats->{bouncedpct} = int(.5 + 100*($stats->{numbered} / $stats->{span}));
  }

  $stats->{maxcount} = $maxbouncecount;
  $stats->{day} = 0;
  $stats->{week} = 0;
  $stats->{month} = 0;

  # Extract breakdown by time
  for $i (@{$bdata->{UM}}, @times) {
    if (($now - $i) < 24*60*60) { # one day
      $stats->{day}++;
    }
    if (($now - $i) < 7*24*60*60) {
      $stats->{week}++;
    }
    if ($do_month && ($now - $i) < 30*24*60*60) {
      $stats->{month}++;
    }
  }
  $stats->{day_overload}   = ($stats->{day}   >= $maxbouncecount)?'>':'';
  $stats->{week_overload}  = ($stats->{week}  >= $maxbouncecount)?'>':'';
  $stats->{month_overload} = ($stats->{month} >= $maxbouncecount)?'>':'';

  $stats;
}

=head1 COPYRIGHT

Copyright (c) 1997-2000 Jason Tibbitts for The Majordomo Development
Group.  All rights reserved.

This program is free software; you can redistribute it and/or modify it
under the terms of the license detailed in the LICENSE file of the
Majordomo2 distribution.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the Majordomo2 LICENSE file for more
detailed information.

=cut

1;
#
### Local Variables: ***
### cperl-indent-level:2 ***
### End: ***
