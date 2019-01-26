=head1 NAME

Mj::Addr - Address object for Majordomo

=head1 SYNOPSIS

 Mj::Addr::set_params(%params);
 $addr = new Mj::Addr($string, %params);
 ($ok, $message, $loc) = $addr->valid; # Tests syntactic legality, returns
                                       # problem description and
                                       # location
 $strip   = $addr->strip;        # Remove comments
 $comment = $addr->comment;      # Extract comments

 if ($addr1->canon eq $addr2->canon) {
   # They are, after aliasing and transformation, equivalent
 }

=head1 DESCRIPTION

This module implements an object encapsulating an address.  Majordomo needs
to see several forms of an address at various times, and sometimes needs to
deal with more than one form at a time.  Majordomo needs these forms:

  full - the address and all of its comments
  stripped - the address without its comments
  comments - the comments without the address.  Note that you cannot deduce
             the full address from the stripped address and the comments.
  transformed - the address after transformations have been applied.
  canonical - the stripped address after both aliasing and transformation
              have taken place.  All comparisons should happen on canonical
              addresses, and can be carried out by comparing stringwise.

Majordomo also needs to check whether or not an address is valid, and upon
encountering an invalid address have access to a user-friendly (or at least
somewhat explanatory) message as to the nature of the syntactic anomaly.

=cut

package Mj::Addr;
use strict;
use vars qw($addr %defaults %top_level_domains);
#use Mj::Log;
use overload
  '=='   => \&match,
  'eq'   => \&match,
  '""'   => \&full,
  'bool' => \&isvalid;

# Some reasonable defaults; still require xforms and an aliaslist
%defaults = ('allow_at_in_phrase'          => 0,
	     'allow_bang_paths'            => 0,
	     'allow_comments_after_route'  => 0,
	     'allow_ending_dot'            => 0,
	     'limit_length'                => 1,
	     'require_fqdn'                => 1,
	     'strict_domain_check'         => 1,
	    );

=head2 set_params

This sets the defaults for all Mj::Addr objects allocated afterwards.  It
takes a hash of parameter, value pairs.  The parameters can be set all at
once or at various times.

The following parameters can be set to either 0 or 1:

  allow_at_in_phrase         - Allow '@' in the 'phrase' part of addresses
                               like this:   ph@rase <user@example.com>
  allow_bang_paths           - Allow old-style UUCP electronic-mail
                               addresses like this:  abcvax!defvax!user
  allow_comments_after_route - Allow (illegal) e-mail addresses like this:
                                 <user@example.com> comment
                               (the address is illegal because the comment
                               should be before the <user@example.com>
                               part and not after it.)
  allow_ending_dot           - Allow a dot at the end of an e-mail address
                               e.g. like this:  user@example.com.
  limit_length               - Limit the length of 'user' and 'host' parts
                               of user@host e-mail addresses to 64
                               characters each, as required by section
                               4.5.3 of RFC821.
  require_fqdn               - Require fully qualified domain names.
  strict_domain_check        - Check for valid top-level domain and for
                               correct syntax of domain-literals.

  NOTE: Checking for a valid top-level domain is currently done by means of
        a table which is hard-coded at the end of this file, and which might
        possibly be outdated by the time you''re reading this.

The following parameters take other values:

  aliaslist - a reference to a Mj::AliasList object, used to perform alias
              lookups.

  xforms    - a reference to an array of address transforms, described in
              the Majordomo config file.

Example, illustrating the default settings:
  Mj::Addr::set_params
    (
     allow_at_in_phrase          => 0,
     allow_bang_paths            => 0,
     allow_comments_after_route  => 0,
     allow_ending_dot            => 0,
     limit_length                => 1,
     require_fqdn                => 1,
     strict_domain_check         => 1,
    );

=cut
sub set_params {
  my %params = @_;
  my($key, $val);
  while (($key, $val) = each %params) {
    $defaults{$key} = $val;
  }
}

=head2 new($addr, %params)

This allocates and returns an Mj::Addr object using the given string as the
address.  Parameters not mentioned will be filled in with the defaults or
any previously set parameters.  If the passed valie is already an Mj::Addr
object, it will just be returned.  This lets you do

  $addr = new Mj::Addr($addr)

without worring about whether you were passed an address or not.  Cached
data is preserved by this, too.

The string does not have to be a valid address, but various calls will
return undef if it is not.  If having a valid address is important, a call
to the 'valid' method should be made shortly afterwards.

Class layout (hash):
  p - hashref parameters
  cache - hashref of cached data
  full - the full address
  strip - the stripped address
  comment - the comments
  xform - the transformed address
  alias - the full form of the address after aliasing
  canon - the canonical address (stripped form of address after aliasing)

  parsed - has the full address been parsed yet?
  valid  - is the address valid
  message - syntax error message

Only canonical addresses should be used for comparison.

The cache field is intended to be used to stuff additional data in an
address, so that it can carry it along as it is passed throughout the
system.  This is intended to eliminate some needless calls to retrieve
flags and such.

Be aware of stale data; these addresses will accumulate information and
cache it; this saves time but can cause interesting problems if the cached
data is outdated.  These objects should probably not live very long lives.
They should definitely not be cached between connections.

=cut
sub new {
  my $type  = shift;
  my $class = ref($type) || $type;
  my $self  = {};
  my $val = shift;
  my $key;

  # Bail if creating an Addr from an Addr
  return $val if (ref ($val) eq 'Mj::Addr');
  return unless (defined $val);

  # Unfold by removing only the CRLF.
  # (This is consistent with RFC 2822.)
  $val =~ s/\r?\n(\s)/$1/gs;

  # Untaint
  $val =~ /(.*)/; $val = $1 || "";
  # Avoid database overlaps.
  $val =~ s/\001/^A/g;

  $self->{'full'} = $val;
  return undef unless $self->{'full'};
#  my $log = new Log::In 150, $self->{'full'};
  bless $self, $class;

  if ($val =~ /(.+)\@anonymous$/) {
    $self->{'aliased'} = 1;
    $self->{'anon'} = 1;
    $self->{'parsed'} = 1;
    $self->{'valid'} = 1;
    $self->{'xformed'} = 1;
    $self->{'canon'} = $val;
    $self->{'strip'} = $val;
    $self->{'xform'} = $val;
    $self->{'local_part'} = $1;
    $self->{'domain'} = 'anonymous';
  }

  # Copy in defaults, then override.
  while (($key, $val) = each %defaults) {
    $self->{p}{$key} = $val;
  }
  while (@_) {
    ($key, $val) = splice(@_, 0, 2);
    $self->{p}{$key} = $val;
  }
  $self;
}

=head2 separate(string)

This takes a string, assumed to be a comma-separated list of addresses, and
returns a list containing the separate addresses.  Because of the bizarre
nature of RFC822 addresses, this is not a simple matter.

The returned values are strings, _NOT_ Mj::Addr objects.  They may or may
not be valid because only enough of the validation procedure to determine
where the splits occur is run.  If the procedure does detect an invalid
address, it will return the separated addresses to the left of the error
but not anything else.  The returned strings may or not be stripped
addresses; parenthesized comments will be removed but route addresses
will be left whole.

=cut
sub separate {
  my $str = shift;
  my(@out, $addr, $ok, $rest, $self);
  # Fake an addr object so we can call _validate
  $self = new Mj::Addr('unknown@anonymous');

  while (1) {
    $self->{'full'} = $str;
    ($ok, undef, $addr, $rest) = $self->_validate;
    # Three possibilities:
    if ($ok == 0) {
      # Some kind of syntax failure; bail with what we have
      return @out;
    }
    elsif ($ok > 0) {
      # The string was a real, valid address and there is no more to split
      $str =~ s/^\s+//; $str =~ s/\s+$//;
      push @out, $str;
      return @out;
    }
    else { # $ok < 0
      # Stripped one address; more to check
      push @out, $addr;
      $str = $rest;
    }
  }
}

=head2 reset(addr)

Clears out any cached data and resets the address to a new string.  This
has less overhead than destroying and creating anew large numbers of
Mj::Addr objects in a loop.

If $addr is not defined, just resets the cached data.

=cut
sub reset {
  my $self = shift;
  my $addr = shift;
#  my $log = new Log::In 150, $self->{'full'};

  delete $self->{'cache'};
  if ($addr) {
    $self->{'full'} = $addr;

    if ($addr =~ /(.+)\@anonymous$/) {
      $self->{'aliased'} = 1;
      $self->{'anon'} = 1;
      $self->{'parsed'} = 1;
      $self->{'valid'} = 1;
      $self->{'xformed'} = 1;
      $self->{'canon'} = $addr;
      $self->{'strip'} = $addr;
      $self->{'xform'} = $addr;
      $self->{'local_part'} = $1;
      $self->{'domain'} = 'anonymous';
    }

    else {
      delete $self->{'alias'};
      delete $self->{'canon'};
      delete $self->{'comment'};
      delete $self->{'domain'};
      delete $self->{'local_part'};
      delete $self->{'strip'};
      delete $self->{'xform'};
      delete $self->{'valid'};
      $self->{'parsed'} = 0;
      $self->{'aliased'} = 0;
      $self->{'xformed'} = 0;
    }
  }
}

=head2 setcomment(comment)
   
This changes the comment portion of an address.  As a side effect, it
will coerce the full address to name-addr form.

=cut
sub setcomment {
  my $self    = shift;
  my $comment = shift;
  my ($newaddr, $loc, $mess, $ok, $orig, $strip);

  $comment =~ s/^\s*["'](.*)["']\s*$/$1/;

  $strip = $self->strip;
  $orig = $self->full;

  # Add quotes to the comment if it contains special characters
  # and is not already quoted.
  if ($comment =~ /[^\w\s!#\$\%\&\@'*+\-\/=?\^`\{\}|~]/
      and $comment !~ /^\s*".*"\s*$/) {
    $newaddr = qq("$comment" <$strip>);
  }
  else {
    $newaddr = qq($comment <$strip>);
  }

  $self->reset($newaddr);

  ($ok, $mess, $loc) = $self->valid;
  unless ($ok) {
    $self->reset($orig);
  }

  return ($ok, $mess, $loc);
}

=head2 full

Extracts the full address.  This is in all cases just the string that was
passed in when the object was created.

=cut
sub full {
  my $self = shift;
#  my $log = new Log::In 150, $self->{'full'};
  $self->{'full'};
}

=head2 strip

Extracts the stripped address.

=cut
sub strip {
  my $self = shift;
#  my $log = new Log::In 150, $self->{'full'};

  $self->_parse unless $self->{parsed};
  $self->{'strip'};
}

=head2 comment

Extracts the comment.

=cut
sub comment {
  my $self = shift;
#  my $log = new Log::In 150, $self->{'full'};

  $self->_parse unless $self->{parsed};
  $self->{'comment'};
}

=head2 local_part

This routine returns the local part of an address.
For example, the address "fred@example.com" has the local
part "fred".

=cut
sub local_part {
  my $self = shift;
#  my $log = new Log::In 150, $self->{'full'};

  $self->_parse unless $self->{parsed};
  $self->{'local_part'};
}

=head2 domain

This routine returns the domain of an address.
For example, the address "fred@example.com" has the 
domain "example.com".

=cut
sub domain {
  my $self = shift;
#  my $log = new Log::In 150, $self->{'full'};

  $self->_parse unless $self->{parsed};
  $self->{'domain'};
}

=head2 valid, isvalid

Verifies that the address is valid and returns a list:
  flag    - true if the address is valid.
  message - a syntax error if the message is invalid.

isvalid returns only the flag.

=cut
sub valid {
  my $self = shift;
#  my $log = new Log::In 150, $self->{'full'};

#  use Data::Dumper; print Dumper $self;

  $self->_parse unless $self->{parsed};
  ($self->{'valid'}, $self->{message}, $self->{'error_location'});
}

sub isvalid {
  my $self = shift;
#  my $log = new Log::In 150, $self->{'full'};

  $self->_parse unless $self->{parsed};
  $self->{'valid'};
}

=head2 isanon

Returns true if the address is anonymous.

=cut
sub isanon {
  my $self = shift;
  return $self->{'anon'};
}

=head2 xform

Returns the transformed form of the address.  This will be equivalent to
the stripped form unless the xform parameter is set to something which
modifies the address.

=cut
sub xform {
  my $self = shift;
#  my $log = new Log::In 150, $self->{'full'};

  $self->_xform unless $self->{xformed};
  $self->{'xform'};
}

=head2 alias

Returns the aliased form of the address; that is, the full address
including comments that the address is aliased to.

=cut
sub alias {
  my $self = shift;
#  my $log = new Log::In 150, $self->{'full'};

  $self->_alias unless $self->{aliased};
  $self->{alias};
}

=head2 canon

Returns the canonical form of the address.  Will be the same as the xform
form unless the aliaslist parameter is set and the address aliases to
something.

=cut
sub canon {
  my $self = shift;
#  my $log = new Log::In 150, $self->{'full'};
  $self->_alias unless $self->{aliased};
  $self->{'canon'};
}

=head2 cache($tag, $data)

Caches some data within the Mj::Addr object.

=cut
sub cache {
  my ($self, $tag, $data) = @_;
#  my $log = new Log::In 150, $self->{'full'};
  $self->{'cache'}{$tag} = $data;
}

=head2 retrieve($tag)

Retrieves some cached data.

=cut
sub retrieve {
  my ($self, $tag) = @_;
#  my $log = new Log::In 150, "$self->{'full'}, $tag";
  $self->{'cache'}{$tag};
}

=head2 flush

Deletes any cached data.

=cut
sub flush {
  my $self = shift;
  delete $self->{'cache'};
}

=head2 match($addr1, $addr2)

Returns true if two Mj::Addr objects are equivalent, false otherwise.

=cut
sub match {
  my ($a1, $a2) = @_;

  return 0 unless $a1->isvalid;
  return 0 if     $a1->isanon;

  if (ref $a2 eq 'Mj::Addr') {
    return 0 unless $a2->isvalid;
    return 0 if     $a2->isanon;

    return $a1->canon eq $a2->canon;
  }
  $a1->canon eq $a2;
}

=head2 _parse

Parse an address, extracting the valid flag, a syntax error (if any), the
stripped address, the comments, and the local part.

=cut
sub _parse {
  my $self = shift;

  my ($ok, $v1, $v2, $v3, $v4) = $self->_validate;

  if ($ok > 0) {
    $self->{'strip'}   = $v1;
    $self->{'comment'} = $v2;
    $self->{'local_part'} = $v3;
    $self->{'domain'}   = $v4;
    $self->{'valid'}   = 1;
    $self->{'message'} = '';
    $self->{'error_location'} = '';
  }
  else {
    $self->{'strip'}   = undef;
    $self->{'comment'} = undef;
    $self->{'local_part'} = undef;
    $self->{'domain'}  = undef;
    $self->{'valid'}   = 0;
    $self->{'message'} = $v1;
    $self->{'error_location'} = $v2;
  }
  $self->{'parsed'} = 1;
  $self->{'valid'};
}

=head2 _xform

Apply transformations (if any) to the address.  They are applied in order;
care should be taken that they are idempotent and that the collection is
idempotent.  This means that the result of applying them repeatedly is the
same as the result of applying them once.

Transformations look somewhat like the usual regular expression transforms:

/(.*?)\+.*(\@.*)/$1$2/

removes the sendmail +mailbox specifier from the address, which turns
tibbs+blah@hurl.edu into tibbs@hurl.edu.  Note that applying this
repeatedly leaves the address alone.  When there is more than one plus, all
are removed.

/(.*\@).*?\.(hurl\.edu)/$1$2/

Removes the machine name from the hurl.edu domain, which turns
tibbs@a2.hurl.edu into tibbs@hurl.edu.  Note that applying this repeatedly
leaves the address alone.

No transformations are necessary to downcase hostnames in addresses; that
is done automatically by the address parser.

=cut
sub _xform {
  my $self = shift;
  my (@xforms, $cpt, $i, $eval);

#  my $log = new Log::In 120, $self->{'full'};

  # Parse the address if we need to; bomb if it is invalid
  return 0 unless $self->isvalid;

  # Exit successfully if we have nothing to do
  unless ($self->{p}{xforms} && @{$self->{p}{xforms}}) {
    $self->{'xform'} = $self->{'strip'};
    return 1;
  }

  local $addr = $self->{'strip'};

  # Set up the Safe compartment
  eval { require Safe; $cpt = new Safe; };
  $cpt->permit_only(qw(concat const lc leaveeval lineseq list multideref padany
                       pushmark rv2sv subst uc rv2gv));
  $cpt->share('$addr');

  for $i (@{$self->{p}{xforms}}) {
    # Do the substitution in a _very_ restrictive Safe compartment
    $eval = "\$addr =~ s$i";
    $cpt->reval($eval);

    # Log any messages
    if ($@) {
warn $@;
#      $::log->message(10,
#		      "info",
#		      "Mj::Addr::xform: error in Safe compartment: $@"
#		     );
    }
  }
  $self->{'xform'} = $addr;
  1;
}

=head2 _alias

Do an alias lookup on an address.

=cut
sub _alias {
  my $self = shift;
  my $data;
#  my $log = new Log::In 150, $self->{'full'};

  # Make sure we've transformed first, and bomb if we can't.
  unless ($self->{xformed}) {
    return 0 unless $self->_xform;
  }

  # Copy over unaliased values and exit if we have nothing to do
  unless ($self->{p}{aliaslist}) {
    $self->{'canon'} = $self->{'xform'};
    $self->{'alias'} = $self->{'xform'};
    return 1;
  }

  $data = $self->{p}{aliaslist}->lookup($self->{'xform'});

  # Use the alias data except for bookkeeping aliases
  if ($data and $self->{'xform'} ne $data->{'target'}) {
    $self->{'canon'} = $data->{target};
    $self->{'alias'} = $data->{striptarget};
  }
  else {
    $self->{'canon'} = $self->{'xform'};
    $self->{'alias'} = $self->{'xform'};
  }
  $self->{aliased} = 1;
  1;
}

=head2 validate (internal method)

Intended to check an address for validity and report back problems in a way
that the user can understand.  This is hard to do.  This routine tries to
do a "good job" in that it catches most forms of bad addresses and doesn''t
trap anything that is legal.  Some configuration variables are provided to
control certain aspects of its behavior and to allow certain types of
illegal addresses that are commonly allowed.

It currently does not properly handle non-ASCII characters in comments and
hostnames, nor does it handle address groups and route addresses with more
than one host.

When a list of addresses separated by a comma is detected, a special error
value is returned along with a normal error message, the portion of the
address to the left of the comma and the portion to the right.  This can be
used to chip addresses off of the left hand side of an address list.

=cut

sub _validate {
  my $self  = shift;
  local($_) = $self->{'full'};
#  my $log = new Log::In 150, $_;
  my (@comment, @phrase, @route, @words, $angle, $bang_path, $comment,
      $domain_literal, $i, $right_of_route, $lhs_length, $nest, $rhs_length,
      $on_rhs, $subdomain, $word);

  my $specials    = q|()<>@,;:\".[]|;
  my $specials_nd = q|()<>@,;:\"[]|;  # No dot
  $lhs_length = $rhs_length = 0;

  # We'll be interpolating arrays into strings and we don't want any
  # spaces.
  local($") = ''; 

  # Trim leading and trailing whitespace; it hoses the algorithm
  s/^\s+//;
  s/\s+$//;

  if ($_ eq "") {
#    $log->out("failed");
    return (0, 'undefined_address');
  }

  # We split the address into "words" of either atoms, quoted strings,
  # domain literals or parenthesized comments.  In the process we have an
  # implicit check for balance.
  # During tokenization, the following arrays are maintained:
  #  @comment - holds parenthesized comments
  #  @route   - holds elements of a route address
  #  @phrase  - holds all elements outside of a route address
  #  @words   - holds all but parenthesized comments
  # Later a determination of which holds the correct information is made.

  while ($_ ne "") {
    $word = "";
    s/^\s+//;  # Trim leading whitespace

    # Handle (ugh) nested parenthesized comments.  Man, RFC822 sucks.
    # Nested comments???  We do this first because otherwise the
    # parentheses get parsed separately as specials.  (Pulling out the
    # comments whole makes things easier.)
    if (/^\(/) {
      $comment = "";
      $nest = 0;
      while (s/^(\(([^\\\(\)]|\\.)*)//) {
	$comment .= $1;
	$nest++;
	while ($nest && s/^(([^\\\(\)]|\\.)*\)\s*)//) {
	  $nest--;
	  $comment .= $1;
	}
      }

      # If we don't have enough closing parentheses, we're hosed
      if ($nest) {
#	$log->out("failed");
	return (0, 'unmatched_paren', "$comment $_");
      }

      # Trim parentheses and trailing space from the comment
      $comment =~ s/^\(//;
      $comment =~ s/\)\s*$//;
      push @comment, $comment;
      push @phrase,  $comment;
      next;
    }

    # Quoted strings are words; this leaves the quotes on the word/atom
    # unless it's part of the phrase.  XXX req #3
    if (s/^(\"(([^\"\\]|\\.)*)\")//) {
      push @words,  $1;
      push @phrase, $2 if !$angle;
      push @route,  $1 if $angle;
      next;
    }

    # Domain literals are words, but are only legal on the right hand side
    # of a mailbox.
    if (s/^(\[([^\[\\]|\\.)*\])//) {
      push @words,  $1;
      push @phrase, $1 if $angle;
      push @route,  $1 if $angle;

      unless ($on_rhs) {
#	$log->out("failed");
	return (0, 'lhs_domain_literal', "$1 $_");
      }
      unless ($words[-2] && $words[-2] =~ /^[.@]/) {
#	$log->out("failed");
	return (0, 'rhs_domain_literal', "$words[-2] _$1_$_");
      }
      next;
    }

    # Words made up of legal characters
    if (s/^(([^\s\Q$specials\E])+)//) {
      push @words,  $1;
      push @phrase, $1 if !$angle;
      push @route,  $1 if $angle;
      next;
    }

    # Single specials
    if (s/^([\Q$specials\E])//) {
      push @words, $1;
      push @route, $1 if $angle;

      # Deal with certain special specials

      # According to RFC2822, dots are now legal in a phrase
      #if ($1 eq '.') {
      #push @phrase, $1 if !$angle;
      #}

      # We disallow multiple addresses in From, Reply-To, or a sub/unsub
      # operation.

      # XXX #17 need to do something different here when in a route.
      if ($1 eq ',') {
#	$log->out("failed");
	if ($angle) {
	  return (0, 'source_route', "@words[0..$#words-1] _$1_ $_");
	}
	pop @words;
	return (-1, 'multiple_addresses', join('',@words), $_);
      }

      # An '@' special puts us on the right hand side of an address
      if ($1 eq '@') {

	# But we might already be on the RHS
	if ($on_rhs) {
	  return (0, 'at_symbol', "$words[-1] _$1_ $_");
	}
	$on_rhs = 1;
      }

      # The specials are only allowed between two atoms (comments ignored),
      # but we only have the one to the right to look at.  So we make sure
      # that this special doesn't fall next to another one.
      # Deal with angle brackets (they must nest) and we can only have one
      # bracketed set in an address
      elsif ($1 eq '<') {
	$angle++;
	if ($angle > 1) {
#	  $log->out("failed");
	  return (0, 'nested_brackets', "$words[-2] _$1_ $_");
	}

	# Make sure we haven't already seen a route address
	if (@route) {
#	  $log->out("failed");
	  return (0, 'bracketed_addresses',  "@words[0..$#words-1] _$1_ $_");
	}

      }
      elsif ($1 eq '>') {
	$angle--;
	pop @route;
	if ($angle < 0) {
#	  $log->out("failed");
	  return (0, 'right_brackets', sprintf ("%s_%s_%s",
			    $words[-2] || "", $1, $_));
	}
	next;
      }

      # The following can be if instead of elsif, but we choose to postpone
      # some tests until later to give better messages.
      elsif ($words[-2] && $words[-2] =~ /^[\Q$specials\E]$/) {
#	$log->out("failed");
	return (0, 'invalid_char', sprintf("%s _%s %s_ %s",
                   $words[-3] || "", $words[-2], $words[-1], $_));
      }
      next;
    }

#    $log->out("failed");
    return (0, 'invalid_component', $_);
  }
  if ($angle) {
#    $log->out("failed");
    return (0, 'left_brackets', '<');
  }

  # So we have the address broken into pieces and have done a bunch of
  # syntax checks.  Now we decide if we have a route address or a simple
  # mailbox, check syntax accordingly, and build the address.

  if (@route) {
    # A route address was found during tokenizing.  We know that the @words
    # list has only one '<>' bracketed section, so we scan everything else
    # for specials and if none are found then the address is legal.
    $angle = 0;
    for $i (0..$#words) {

      # Quoted strings are OK, I think.
      next if $words[$i] =~ /^\"/;

      if ($words[$i] =~ /^\</) {
	$angle++;
	next;
      }
      if ($words[$i] =~ /^\>/) {
	$angle--;
	$right_of_route = 1;
	next;
      }

      # If in a bracketed section, specials are OK.
      next if $angle;

      # If we're right of the route address, nothing is allowed to appear.
      # This is common, however, and is overrideable.
      if (!$self->{p}{'allow_comments_after_route'} && $right_of_route) {
#	$log->out("failed");
	return (0, 'after_route', $words[$i]);
      }

      # We might be lenient and allow '@' in the phrase
      if ($self->{p}{'allow_at_in_phrase'} && $words[$i] =~ /^\@/) {
	next;
      }

      # Other specials are illegal
      if ($words[$i] =~ /^[\Q$specials_nd\E]/) {
#	$log->out("failed");
	return (0, 'invalid_char', sprintf("%s _%s_ %s", $words[$i-1] || "", 
                                           $words[$i], $words[$i+1] || ""));
      }
    }
    # We toss the other tokens, since we don't need them anymore.
    @words   = @route;
    @comment = @phrase;
  }
  # We have an addr-spec.  The address is then everything that isn't a
  # comment.  XXX We should make special allowances for the weird
  # @domain,@domain,@domain:addr@domain syntax.

  unless (@words) {
#    $log->out("failed");
    return (0, 'no_route', '');
  }

  # In an addr-spec, every atom must be separated by either a '.' (dots are
  # OK on the LHS) or a '@', there must be only a single '@', the address
  # must begin and end with an atom.  (We can be lenient and allow it to
  # end with a '.', too.)
  if ($words[0] =~ /^[.@]/) {
#    $log->out("failed");
    return (0, 'starting_char', $words[0]);
  }

  $on_rhs = 0;

  # We can bail out early if we have just a bang path
  if ($#words == 0 &&
      $self->{p}{'allow_bang_paths'} &&
      $words[0] =~ /[a-z0-9]\![a-z]/i)
    {
#      $log->out;
      return (1, $words[0], join(" ", @comment)||"");
    }

  for $i (0..$#words) {
    if ($i > 0 &&$words[$i] !~ /^[.@]/ && $words[$i-1] && $words[$i-1] !~ /^[.@]/) {
#      $log->out("failed");
      return (0, 'word_separator', "$words[$i-1] $words[$i]");
    }

    if ($words[$i] eq '@') {
      $on_rhs = 1;
      next;
    }

    if($on_rhs) {
      $words[$i] = lc($words[$i]);
      $rhs_length += length($words[$i]);
      if ($self->{p}{'limit_length'} && $rhs_length > 64) {
#	$log->out("failed");
	return (0, 'host_length', $words[$i]);
      }
      # Hostname components must be only alphabetics, ., or -; can't start
      # with -.  We also allow '[' and ']' for domain literals.
      if (($words[$i] =~ /[^a-zA-Z0-9.-]/ ||
	   $words[$i] =~ /^-/) && $words[$i] !~ /^[\[\]]/)
	{
#	  $log->out("failed");
	  return (0, 'invalid_char', "$words[$i]");
	}
    }
    else {
      $lhs_length += length($words[$i]);
      if ($self->{p}{'limit_length'} && $lhs_length > 64) {
#	$log->out("failed");
	return (0, 'local_part_length', $words[$i]);
      }
      # Username components must lie betweem 040 and 0177.  (It's really
      # more complicated than that, but this will catch most of the
      # problems.)
      if ($words[$i] =~ /[^\040-\177]/) {
#	$log->out("failed");
	return (0, 'invalid_char', "$words[$i]");
      }
    }

    if ($words[$i] !~ /^[.@]/ && $on_rhs) {
      $subdomain++;
    }

    if ($on_rhs && $words[$i] =~ /^\[/) {
      $domain_literal = 1;
    }
  }

  if ($self->{p}{'require_fqdn'} && !$on_rhs) {
    if ($top_level_domains{lc($words[-1])}) {
#      $log->out("failed");
      return (0, 'no_local_part', $words[-1]);
    }
    else {
#      $log->out("failed");
      return (0, 'no_domain', $words[-1]);
    }
  }

  if ($words[-1] eq '@') {
#    $log->out("failed");
    return (0, 'ending_at', '@');
  }

  if (!$self->{p}{'allow_ending_dot'} && $words[-1] eq '.') {
#    $log->out("failed");
    return (0, 'ending_period', '.');
  }

  # Now check the validity of the domain part of the address.  If we've
  # seen a domain-literal, all bets are off.  Don't bother if we never even
  # got to the right hand side; this case will have bombed out earlier of a
  # domain name is required.
  if ($on_rhs) {
    if ($self->{p}{'require_fqdn'} && $subdomain < 2 && !$domain_literal) {
#      $log->out("failed");
      return (0, 'incomplete_host', $words[-1]);
    }
    if (($self->{p}{'strict_domain_check'} &&
	 $words[-1] !~ /^\[/ &&
	 !$top_level_domains{lc($words[-1])}) ||
	$words[-1] !~ /[\w-]{2,5}/)
      {
	if ($words[-1] !~ /\D/ &&
	    $words[-3] && $words[-3] !~ /\D/ &&
	    $words[-5] && $words[-5] !~ /\D/ &&
	    $words[-7] && $words[-7] !~ /\D/)
	  {
#	    $log->out("failed");
	    return (0, 'ip_address', join("",@words[-7..-1]));
	  }
	
#	$log->out("failed");
	return (0, 'top_level_domain', $words[-1]);
      }
  }

  my $addr = join("", @words);
  my $comm = join(" ", @comment) || "";
  my $lp   = substr $addr, 0, $lhs_length;
  my $dom  = substr $addr, -$rhs_length, $rhs_length;

#  $log->out('ok');
  (1, $addr, $comm, $lp, $dom);
}

%top_level_domains =
  (
   'aaa'            => 1,
   'aarp'           => 1,
   'abarth'         => 1,
   'abb'            => 1,
   'abbott'         => 1,
   'abbvie'         => 1,
   'abc'            => 1,
   'able'           => 1,
   'abogado'        => 1,
   'abudhabi'       => 1,
   'ac'             => 1,
   'academy'        => 1,
   'accenture'      => 1,
   'accountant'     => 1,
   'accountants'    => 1,
   'aco'            => 1,
   'active'         => 1,
   'actor'          => 1,
   'ad'             => 1,
   'adac'           => 1,
   'ads'            => 1,
   'adult'          => 1,
   'ae'             => 1,
   'aeg'            => 1,
   'aero'           => 1,
   'aetna'          => 1,
   'af'             => 1,
   'afamilycompany' => 1,
   'afl'            => 1,
   'africa'         => 1,
   'ag'             => 1,
   'agakhan'        => 1,
   'agency'         => 1,
   'ai'             => 1,
   'aig'            => 1,
   'aigo'           => 1,
   'airbus'         => 1,
   'airforce'       => 1,
   'airtel'         => 1,
   'akdn'           => 1,
   'al'             => 1,
   'alfaromeo'      => 1,
   'alibaba'        => 1,
   'alipay'         => 1,
   'allfinanz'      => 1,
   'allstate'       => 1,
   'ally'           => 1,
   'alsace'         => 1,
   'alstom'         => 1,
   'am'             => 1,
   'americanexpress' => 1,
   'americanfamily' => 1,
   'amex'           => 1,
   'amfam'          => 1,
   'amica'          => 1,
   'amsterdam'      => 1,
   'an'             => 1,
   'analytics'      => 1,
   'android'        => 1,
   'anquan'         => 1,
   'anz'            => 1,
   'ao'             => 1,
   'aol'            => 1,
   'apartments'     => 1,
   'app'            => 1,
   'apple'          => 1,
   'aq'             => 1,
   'aquarelle'      => 1,
   'ar'             => 1,
   'arab'           => 1,
   'aramco'         => 1,
   'archi'          => 1,
   'army'           => 1,
   'arpa'           => 1,
   'art'            => 1,
   'arte'           => 1,
   'as'             => 1,
   'asda'           => 1,
   'asia'           => 1,
   'associates'     => 1,
   'at'             => 1,
   'athleta'        => 1,
   'attorney'       => 1,
   'au'             => 1,
   'auction'        => 1,
   'audi'           => 1,
   'audible'        => 1,
   'audio'          => 1,
   'auspost'        => 1,
   'author'         => 1,
   'auto'           => 1,
   'autos'          => 1,
   'avianca'        => 1,
   'aw'             => 1,
   'aws'            => 1,
   'ax'             => 1,
   'axa'            => 1,
   'az'             => 1,
   'azure'          => 1,
   'ba'             => 1,
   'baby'           => 1,
   'baidu'          => 1,
   'banamex'        => 1,
   'bananarepublic' => 1,
   'band'           => 1,
   'bank'           => 1,
   'bar'            => 1,
   'barcelona'      => 1,
   'barclaycard'    => 1,
   'barclays'       => 1,
   'barefoot'       => 1,
   'bargains'       => 1,
   'baseball'       => 1,
   'basketball'     => 1,
   'bauhaus'        => 1,
   'bayern'         => 1,
   'bb'             => 1,
   'bbc'            => 1,
   'bbt'            => 1,
   'bbva'           => 1,
   'bcg'            => 1,
   'bcn'            => 1,
   'bd'             => 1,
   'be'             => 1,
   'beats'          => 1,
   'beauty'         => 1,
   'beer'           => 1,
   'bentley'        => 1,
   'berlin'         => 1,
   'best'           => 1,
   'bestbuy'        => 1,
   'bet'            => 1,
   'bf'             => 1,
   'bg'             => 1,
   'bh'             => 1,
   'bharti'         => 1,
   'bi'             => 1,
   'bible'          => 1,
   'bid'            => 1,
   'bike'           => 1,
   'bing'           => 1,
   'bingo'          => 1,
   'bio'            => 1,
   'biz'            => 1,
   'bj'             => 1,
   'bl'             => 1,
   'black'          => 1,
   'blackfriday'    => 1,
   'blanco'         => 1,
   'blockbuster'    => 1,
   'blog'           => 1,
   'bloomberg'      => 1,
   'blue'           => 1,
   'bm'             => 1,
   'bms'            => 1,
   'bmw'            => 1,
   'bn'             => 1,
   'bnl'            => 1,
   'bnpparibas'     => 1,
   'bo'             => 1,
   'boats'          => 1,
   'boehringer'     => 1,
   'bofa'           => 1,
   'bom'            => 1,
   'bond'           => 1,
   'boo'            => 1,
   'book'           => 1,
   'booking'        => 1,
   'boots'          => 1,
   'bosch'          => 1,
   'bostik'         => 1,
   'boston'         => 1,
   'bot'            => 1,
   'boutique'       => 1,
   'box'            => 1,
   'bq'             => 1,
   'br'             => 1,
   'bradesco'       => 1,
   'bridgestone'    => 1,
   'broadway'       => 1,
   'broker'         => 1,
   'brother'        => 1,
   'brussels'       => 1,
   'bs'             => 1,
   'bt'             => 1,
   'budapest'       => 1,
   'bugatti'        => 1,
   'build'          => 1,
   'builders'       => 1,
   'business'       => 1,
   'buy'            => 1,
   'buzz'           => 1,
   'bv'             => 1,
   'bw'             => 1,
   'by'             => 1,
   'bz'             => 1,
   'bzh'            => 1,
   'ca'             => 1,
   'cab'            => 1,
   'cafe'           => 1,
   'cal'            => 1,
   'call'           => 1,
   'calvinklein'    => 1,
   'cam'            => 1,
   'camera'         => 1,
   'camp'           => 1,
   'cancerresearch' => 1,
   'canon'          => 1,
   'capetown'       => 1,
   'capital'        => 1,
   'capitalone'     => 1,
   'car'            => 1,
   'caravan'        => 1,
   'cards'          => 1,
   'care'           => 1,
   'career'         => 1,
   'careers'        => 1,
   'cars'           => 1,
   'cartier'        => 1,
   'casa'           => 1,
   'case'           => 1,
   'caseih'         => 1,
   'cash'           => 1,
   'casino'         => 1,
   'cat'            => 1,
   'catering'       => 1,
   'catholic'       => 1,
   'cba'            => 1,
   'cbn'            => 1,
   'cbre'           => 1,
   'cbs'            => 1,
   'cc'             => 1,
   'cd'             => 1,
   'ceb'            => 1,
   'center'         => 1,
   'ceo'            => 1,
   'cern'           => 1,
   'cf'             => 1,
   'cfa'            => 1,
   'cfd'            => 1,
   'cg'             => 1,
   'ch'             => 1,
   'chanel'         => 1,
   'channel'        => 1,
   'charity'        => 1,
   'chase'          => 1,
   'chat'           => 1,
   'cheap'          => 1,
   'chintai'        => 1,
   'chloe'          => 1,
   'christmas'      => 1,
   'chrome'         => 1,
   'chrysler'       => 1,
   'church'         => 1,
   'ci'             => 1,
   'cipriani'       => 1,
   'circle'         => 1,
   'cisco'          => 1,
   'citadel'        => 1,
   'citi'           => 1,
   'citic'          => 1,
   'city'           => 1,
   'cityeats'       => 1,
   'ck'             => 1,
   'cl'             => 1,
   'claims'         => 1,
   'cleaning'       => 1,
   'click'          => 1,
   'clinic'         => 1,
   'clinique'       => 1,
   'clothing'       => 1,
   'cloud'          => 1,
   'club'           => 1,
   'clubmed'        => 1,
   'cm'             => 1,
   'cn'             => 1,
   'co'             => 1,
   'coach'          => 1,
   'codes'          => 1,
   'coffee'         => 1,
   'college'        => 1,
   'cologne'        => 1,
   'com'            => 1,
   'comcast'        => 1,
   'commbank'       => 1,
   'community'      => 1,
   'company'        => 1,
   'compare'        => 1,
   'computer'       => 1,
   'comsec'         => 1,
   'condos'         => 1,
   'construction'   => 1,
   'consulting'     => 1,
   'contact'        => 1,
   'contractors'    => 1,
   'cooking'        => 1,
   'cookingchannel' => 1,
   'cool'           => 1,
   'coop'           => 1,
   'corsica'        => 1,
   'country'        => 1,
   'coupon'         => 1,
   'coupons'        => 1,
   'courses'        => 1,
   'cr'             => 1,
   'credit'         => 1,
   'creditcard'     => 1,
   'creditunion'    => 1,
   'cricket'        => 1,
   'crown'          => 1,
   'crs'            => 1,
   'cruise'         => 1,
   'cruises'        => 1,
   'csc'            => 1,
   'cu'             => 1,
   'cuisinella'     => 1,
   'cv'             => 1,
   'cw'             => 1,
   'cx'             => 1,
   'cy'             => 1,
   'cymru'          => 1,
   'cyou'           => 1,
   'cz'             => 1,
   'dabur'          => 1,
   'dad'            => 1,
   'dance'          => 1,
   'data'           => 1,
   'date'           => 1,
   'dating'         => 1,
   'datsun'         => 1,
   'day'            => 1,
   'dclk'           => 1,
   'dds'            => 1,
   'de'             => 1,
   'deal'           => 1,
   'dealer'         => 1,
   'deals'          => 1,
   'degree'         => 1,
   'delivery'       => 1,
   'dell'           => 1,
   'deloitte'       => 1,
   'delta'          => 1,
   'democrat'       => 1,
   'dental'         => 1,
   'dentist'        => 1,
   'desi'           => 1,
   'design'         => 1,
   'dev'            => 1,
   'dhl'            => 1,
   'diamonds'       => 1,
   'diet'           => 1,
   'digital'        => 1,
   'direct'         => 1,
   'directory'      => 1,
   'discount'       => 1,
   'discover'       => 1,
   'dish'           => 1,
   'diy'            => 1,
   'dj'             => 1,
   'dk'             => 1,
   'dm'             => 1,
   'dnp'            => 1,
   'do'             => 1,
   'docs'           => 1,
   'doctor'         => 1,
   'dodge'          => 1,
   'dog'            => 1,
   'doha'           => 1,
   'domains'        => 1,
   'doosan'         => 1,
   'dot'            => 1,
   'download'       => 1,
   'drive'          => 1,
   'dtv'            => 1,
   'dubai'          => 1,
   'duck'           => 1,
   'dunlop'         => 1,
   'duns'           => 1,
   'dupont'         => 1,
   'durban'         => 1,
   'dvag'           => 1,
   'dvr'            => 1,
   'dz'             => 1,
   'earth'          => 1,
   'eat'            => 1,
   'ec'             => 1,
   'eco'            => 1,
   'edeka'          => 1,
   'edu'            => 1,
   'education'      => 1,
   'ee'             => 1,
   'eg'             => 1,
   'eh'             => 1,
   'email'          => 1,
   'emerck'         => 1,
   'energy'         => 1,
   'engineer'       => 1,
   'engineering'    => 1,
   'enterprises'    => 1,
   'epost'          => 1,
   'epson'          => 1,
   'equipment'      => 1,
   'er'             => 1,
   'ericsson'       => 1,
   'erni'           => 1,
   'es'             => 1,
   'esq'            => 1,
   'estate'         => 1,
   'esurance'       => 1,
   'et'             => 1,
   'etisalat'       => 1,
   'eu'             => 1,
   'eurovision'     => 1,
   'eus'            => 1,
   'events'         => 1,
   'everbank'       => 1,
   'exchange'       => 1,
   'expert'         => 1,
   'exposed'        => 1,
   'express'        => 1,
   'extraspace'     => 1,
   'fage'           => 1,
   'fail'           => 1,
   'fairwinds'      => 1,
   'faith'          => 1,
   'family'         => 1,
   'fan'            => 1,
   'fans'           => 1,
   'farm'           => 1,
   'farmers'        => 1,
   'fashion'        => 1,
   'fast'           => 1,
   'fedex'          => 1,
   'feedback'       => 1,
   'ferrari'        => 1,
   'ferrero'        => 1,
   'fi'             => 1,
   'fiat'           => 1,
   'fidelity'       => 1,
   'fido'           => 1,
   'film'           => 1,
   'final'          => 1,
   'finance'        => 1,
   'financial'      => 1,
   'fire'           => 1,
   'firestone'      => 1,
   'firmdale'       => 1,
   'fish'           => 1,
   'fishing'        => 1,
   'fit'            => 1,
   'fitness'        => 1,
   'fj'             => 1,
   'fk'             => 1,
   'flickr'         => 1,
   'flights'        => 1,
   'flir'           => 1,
   'florist'        => 1,
   'flowers'        => 1,
   'flsmidth'       => 1,
   'fly'            => 1,
   'fm'             => 1,
   'fo'             => 1,
   'foo'            => 1,
   'food'           => 1,
   'foodnetwork'    => 1,
   'football'       => 1,
   'ford'           => 1,
   'forex'          => 1,
   'forsale'        => 1,
   'forum'          => 1,
   'foundation'     => 1,
   'fox'            => 1,
   'fr'             => 1,
   'free'           => 1,
   'fresenius'      => 1,
   'frl'            => 1,
   'frogans'        => 1,
   'frontdoor'      => 1,
   'frontier'       => 1,
   'ftr'            => 1,
   'fujitsu'        => 1,
   'fujixerox'      => 1,
   'fun'            => 1,
   'fund'           => 1,
   'furniture'      => 1,
   'futbol'         => 1,
   'fyi'            => 1,
   'ga'             => 1,
   'gal'            => 1,
   'gallery'        => 1,
   'gallo'          => 1,
   'gallup'         => 1,
   'game'           => 1,
   'games'          => 1,
   'gap'            => 1,
   'garden'         => 1,
   'gb'             => 1,
   'gbiz'           => 1,
   'gd'             => 1,
   'gdn'            => 1,
   'ge'             => 1,
   'gea'            => 1,
   'gent'           => 1,
   'genting'        => 1,
   'george'         => 1,
   'gf'             => 1,
   'gg'             => 1,
   'ggee'           => 1,
   'gh'             => 1,
   'gi'             => 1,
   'gift'           => 1,
   'gifts'          => 1,
   'gives'          => 1,
   'giving'         => 1,
   'gl'             => 1,
   'glade'          => 1,
   'glass'          => 1,
   'gle'            => 1,
   'global'         => 1,
   'globo'          => 1,
   'gm'             => 1,
   'gmail'          => 1,
   'gmbh'           => 1,
   'gmo'            => 1,
   'gmx'            => 1,
   'gn'             => 1,
   'godaddy'        => 1,
   'gold'           => 1,
   'goldpoint'      => 1,
   'golf'           => 1,
   'goo'            => 1,
   'goodhands'      => 1,
   'goodyear'       => 1,
   'goog'           => 1,
   'google'         => 1,
   'gop'            => 1,
   'got'            => 1,
   'gov'            => 1,
   'gp'             => 1,
   'gq'             => 1,
   'gr'             => 1,
   'grainger'       => 1,
   'graphics'       => 1,
   'gratis'         => 1,
   'green'          => 1,
   'gripe'          => 1,
   'grocery'        => 1,
   'group'          => 1,
   'gs'             => 1,
   'gt'             => 1,
   'gu'             => 1,
   'guardian'       => 1,
   'gucci'          => 1,
   'guge'           => 1,
   'guide'          => 1,
   'guitars'        => 1,
   'guru'           => 1,
   'gw'             => 1,
   'gy'             => 1,
   'hair'           => 1,
   'hamburg'        => 1,
   'hangout'        => 1,
   'haus'           => 1,
   'hbo'            => 1,
   'hdfc'           => 1,
   'hdfcbank'       => 1,
   'health'         => 1,
   'healthcare'     => 1,
   'help'           => 1,
   'helsinki'       => 1,
   'here'           => 1,
   'hermes'         => 1,
   'hgtv'           => 1,
   'hiphop'         => 1,
   'hisamitsu'      => 1,
   'hitachi'        => 1,
   'hiv'            => 1,
   'hk'             => 1,
   'hkt'            => 1,
   'hm'             => 1,
   'hn'             => 1,
   'hockey'         => 1,
   'holdings'       => 1,
   'holiday'        => 1,
   'homedepot'      => 1,
   'homegoods'      => 1,
   'homes'          => 1,
   'homesense'      => 1,
   'honda'          => 1,
   'honeywell'      => 1,
   'horse'          => 1,
   'hospital'       => 1,
   'host'           => 1,
   'hosting'        => 1,
   'hot'            => 1,
   'hoteles'        => 1,
   'hotels'         => 1,
   'hotmail'        => 1,
   'house'          => 1,
   'how'            => 1,
   'hr'             => 1,
   'hsbc'           => 1,
   'ht'             => 1,
   'htc'            => 1,
   'hu'             => 1,
   'hughes'         => 1,
   'hyatt'          => 1,
   'hyundai'        => 1,
   'ibm'            => 1,
   'icbc'           => 1,
   'ice'            => 1,
   'icu'            => 1,
   'id'             => 1,
   'ie'             => 1,
   'ieee'           => 1,
   'ifm'            => 1,
   'iinet'          => 1,
   'ikano'          => 1,
   'il'             => 1,
   'im'             => 1,
   'imamat'         => 1,
   'imdb'           => 1,
   'immo'           => 1,
   'immobilien'     => 1,
   'in'             => 1,
   'inc'            => 1,
   'industries'     => 1,
   'infiniti'       => 1,
   'info'           => 1,
   'ing'            => 1,
   'ink'            => 1,
   'institute'      => 1,
   'insurance'      => 1,
   'insure'         => 1,
   'int'            => 1,
   'intel'          => 1,
   'international'  => 1,
   'intuit'         => 1,
   'investments'    => 1,
   'io'             => 1,
   'ipiranga'       => 1,
   'iq'             => 1,
   'ir'             => 1,
   'irish'          => 1,
   'is'             => 1,
   'iselect'        => 1,
   'ismaili'        => 1,
   'ist'            => 1,
   'istanbul'       => 1,
   'it'             => 1,
   'itau'           => 1,
   'itv'            => 1,
   'iveco'          => 1,
   'iwc'            => 1,
   'jaguar'         => 1,
   'java'           => 1,
   'jcb'            => 1,
   'jcp'            => 1,
   'je'             => 1,
   'jeep'           => 1,
   'jetzt'          => 1,
   'jewelry'        => 1,
   'jio'            => 1,
   'jlc'            => 1,
   'jll'            => 1,
   'jm'             => 1,
   'jmp'            => 1,
   'jnj'            => 1,
   'jo'             => 1,
   'jobs'           => 1,
   'joburg'         => 1,
   'jot'            => 1,
   'joy'            => 1,
   'jp'             => 1,
   'jpmorgan'       => 1,
   'jprs'           => 1,
   'juegos'         => 1,
   'juniper'        => 1,
   'kaufen'         => 1,
   'kddi'           => 1,
   'ke'             => 1,
   'kerryhotels'    => 1,
   'kerrylogistics' => 1,
   'kerryproperties' => 1,
   'kfh'            => 1,
   'kg'             => 1,
   'kh'             => 1,
   'ki'             => 1,
   'kia'            => 1,
   'kim'            => 1,
   'kinder'         => 1,
   'kindle'         => 1,
   'kitchen'        => 1,
   'kiwi'           => 1,
   'km'             => 1,
   'kn'             => 1,
   'koeln'          => 1,
   'komatsu'        => 1,
   'kosher'         => 1,
   'kp'             => 1,
   'kpmg'           => 1,
   'kpn'            => 1,
   'kr'             => 1,
   'krd'            => 1,
   'kred'           => 1,
   'kuokgroup'      => 1,
   'kw'             => 1,
   'ky'             => 1,
   'kyoto'          => 1,
   'kz'             => 1,
   'la'             => 1,
   'lacaixa'        => 1,
   'ladbrokes'      => 1,
   'lamborghini'    => 1,
   'lamer'          => 1,
   'lancaster'      => 1,
   'lancia'         => 1,
   'lancome'        => 1,
   'land'           => 1,
   'landrover'      => 1,
   'lanxess'        => 1,
   'lasalle'        => 1,
   'lat'            => 1,
   'latino'         => 1,
   'latrobe'        => 1,
   'law'            => 1,
   'lawyer'         => 1,
   'lb'             => 1,
   'lc'             => 1,
   'lds'            => 1,
   'lease'          => 1,
   'leclerc'        => 1,
   'lefrak'         => 1,
   'legal'          => 1,
   'lego'           => 1,
   'lexus'          => 1,
   'lgbt'           => 1,
   'li'             => 1,
   'liaison'        => 1,
   'lidl'           => 1,
   'life'           => 1,
   'lifeinsurance'  => 1,
   'lifestyle'      => 1,
   'lighting'       => 1,
   'like'           => 1,
   'lilly'          => 1,
   'limited'        => 1,
   'limo'           => 1,
   'lincoln'        => 1,
   'linde'          => 1,
   'link'           => 1,
   'lipsy'          => 1,
   'live'           => 1,
   'living'         => 1,
   'lixil'          => 1,
   'lk'             => 1,
   'llc'            => 1,
   'loan'           => 1,
   'loans'          => 1,
   'locker'         => 1,
   'locus'          => 1,
   'loft'           => 1,
   'lol'            => 1,
   'london'         => 1,
   'lotte'          => 1,
   'lotto'          => 1,
   'love'           => 1,
   'lpl'            => 1,
   'lplfinancial'   => 1,
   'lr'             => 1,
   'ls'             => 1,
   'lt'             => 1,
   'ltd'            => 1,
   'ltda'           => 1,
   'lu'             => 1,
   'lundbeck'       => 1,
   'lupin'          => 1,
   'luxe'           => 1,
   'luxury'         => 1,
   'lv'             => 1,
   'ly'             => 1,
   'ma'             => 1,
   'macys'          => 1,
   'madrid'         => 1,
   'maif'           => 1,
   'maison'         => 1,
   'makeup'         => 1,
   'man'            => 1,
   'management'     => 1,
   'mango'          => 1,
   'map'            => 1,
   'market'         => 1,
   'marketing'      => 1,
   'markets'        => 1,
   'marriott'       => 1,
   'marshalls'      => 1,
   'maserati'       => 1,
   'mattel'         => 1,
   'mba'            => 1,
   'mc'             => 1,
   'mcd'            => 1,
   'mcdonalds'      => 1,
   'mckinsey'       => 1,
   'md'             => 1,
   'me'             => 1,
   'med'            => 1,
   'media'          => 1,
   'meet'           => 1,
   'melbourne'      => 1,
   'meme'           => 1,
   'memorial'       => 1,
   'men'            => 1,
   'menu'           => 1,
   'meo'            => 1,
   'merckmsd'       => 1,
   'metlife'        => 1,
   'mf'             => 1,
   'mg'             => 1,
   'mh'             => 1,
   'miami'          => 1,
   'microsoft'      => 1,
   'mil'            => 1,
   'mini'           => 1,
   'mint'           => 1,
   'mit'            => 1,
   'mitsubishi'     => 1,
   'mk'             => 1,
   'ml'             => 1,
   'mlb'            => 1,
   'mls'            => 1,
   'mm'             => 1,
   'mma'            => 1,
   'mn'             => 1,
   'mo'             => 1,
   'mobi'           => 1,
   'mobile'         => 1,
   'mobily'         => 1,
   'moda'           => 1,
   'moe'            => 1,
   'moi'            => 1,
   'mom'            => 1,
   'monash'         => 1,
   'money'          => 1,
   'monster'        => 1,
   'montblanc'      => 1,
   'mopar'          => 1,
   'mormon'         => 1,
   'mortgage'       => 1,
   'moscow'         => 1,
   'moto'           => 1,
   'motorcycles'    => 1,
   'mov'            => 1,
   'movie'          => 1,
   'movistar'       => 1,
   'mp'             => 1,
   'mq'             => 1,
   'mr'             => 1,
   'ms'             => 1,
   'msd'            => 1,
   'mt'             => 1,
   'mtn'            => 1,
   'mtpc'           => 1,
   'mtr'            => 1,
   'mu'             => 1,
   'museum'         => 1,
   'mutual'         => 1,
   'mutuelle'       => 1,
   'mv'             => 1,
   'mw'             => 1,
   'mx'             => 1,
   'my'             => 1,
   'mz'             => 1,
   'na'             => 1,
   'nab'            => 1,
   'nadex'          => 1,
   'nagoya'         => 1,
   'name'           => 1,
   'nationwide'     => 1,
   'natura'         => 1,
   'navy'           => 1,
   'nba'            => 1,
   'nc'             => 1,
   'ne'             => 1,
   'nec'            => 1,
   'net'            => 1,
   'netbank'        => 1,
   'netflix'        => 1,
   'network'        => 1,
   'neustar'        => 1,
   'new'            => 1,
   'newholland'     => 1,
   'news'           => 1,
   'next'           => 1,
   'nextdirect'     => 1,
   'nexus'          => 1,
   'nf'             => 1,
   'nfl'            => 1,
   'ng'             => 1,
   'ngo'            => 1,
   'nhk'            => 1,
   'ni'             => 1,
   'nico'           => 1,
   'nike'           => 1,
   'nikon'          => 1,
   'ninja'          => 1,
   'nissan'         => 1,
   'nissay'         => 1,
   'nl'             => 1,
   'no'             => 1,
   'nokia'          => 1,
   'northwesternmutual' => 1,
   'norton'         => 1,
   'now'            => 1,
   'nowruz'         => 1,
   'nowtv'          => 1,
   'np'             => 1,
   'nr'             => 1,
   'nra'            => 1,
   'nrw'            => 1,
   'ntt'            => 1,
   'nu'             => 1,
   'nyc'            => 1,
   'nz'             => 1,
   'obi'            => 1,
   'observer'       => 1,
   'off'            => 1,
   'office'         => 1,
   'okinawa'        => 1,
   'olayan'         => 1,
   'olayangroup'    => 1,
   'oldnavy'        => 1,
   'ollo'           => 1,
   'om'             => 1,
   'omega'          => 1,
   'one'            => 1,
   'ong'            => 1,
   'onl'            => 1,
   'online'         => 1,
   'onyourside'     => 1,
   'ooo'            => 1,
   'open'           => 1,
   'oracle'         => 1,
   'orange'         => 1,
   'org'            => 1,
   'organic'        => 1,
   'orientexpress'  => 1,
   'origins'        => 1,
   'osaka'          => 1,
   'otsuka'         => 1,
   'ott'            => 1,
   'ovh'            => 1,
   'pa'             => 1,
   'page'           => 1,
   'pamperedchef'   => 1,
   'panasonic'      => 1,
   'panerai'        => 1,
   'paris'          => 1,
   'pars'           => 1,
   'partners'       => 1,
   'parts'          => 1,
   'party'          => 1,
   'passagens'      => 1,
   'pay'            => 1,
   'pccw'           => 1,
   'pe'             => 1,
   'pet'            => 1,
   'pf'             => 1,
   'pfizer'         => 1,
   'pg'             => 1,
   'ph'             => 1,
   'pharmacy'       => 1,
   'phd'            => 1,
   'philips'        => 1,
   'phone'          => 1,
   'photo'          => 1,
   'photography'    => 1,
   'photos'         => 1,
   'physio'         => 1,
   'piaget'         => 1,
   'pics'           => 1,
   'pictet'         => 1,
   'pictures'       => 1,
   'pid'            => 1,
   'pin'            => 1,
   'ping'           => 1,
   'pink'           => 1,
   'pioneer'        => 1,
   'pizza'          => 1,
   'pk'             => 1,
   'pl'             => 1,
   'place'          => 1,
   'play'           => 1,
   'playstation'    => 1,
   'plumbing'       => 1,
   'plus'           => 1,
   'pm'             => 1,
   'pn'             => 1,
   'pnc'            => 1,
   'pohl'           => 1,
   'poker'          => 1,
   'politie'        => 1,
   'porn'           => 1,
   'post'           => 1,
   'pr'             => 1,
   'pramerica'      => 1,
   'praxi'          => 1,
   'press'          => 1,
   'prime'          => 1,
   'pro'            => 1,
   'prod'           => 1,
   'productions'    => 1,
   'prof'           => 1,
   'progressive'    => 1,
   'promo'          => 1,
   'properties'     => 1,
   'property'       => 1,
   'protection'     => 1,
   'pru'            => 1,
   'prudential'     => 1,
   'ps'             => 1,
   'pt'             => 1,
   'pub'            => 1,
   'pw'             => 1,
   'pwc'            => 1,
   'py'             => 1,
   'qa'             => 1,
   'qpon'           => 1,
   'quebec'         => 1,
   'quest'          => 1,
   'qvc'            => 1,
   'racing'         => 1,
   'radio'          => 1,
   'raid'           => 1,
   're'             => 1,
   'read'           => 1,
   'realestate'     => 1,
   'realtor'        => 1,
   'realty'         => 1,
   'recipes'        => 1,
   'red'            => 1,
   'redstone'       => 1,
   'redumbrella'    => 1,
   'rehab'          => 1,
   'reise'          => 1,
   'reisen'         => 1,
   'reit'           => 1,
   'reliance'       => 1,
   'ren'            => 1,
   'rent'           => 1,
   'rentals'        => 1,
   'repair'         => 1,
   'report'         => 1,
   'republican'     => 1,
   'rest'           => 1,
   'restaurant'     => 1,
   'review'         => 1,
   'reviews'        => 1,
   'rexroth'        => 1,
   'rich'           => 1,
   'richardli'      => 1,
   'ricoh'          => 1,
   'rightathome'    => 1,
   'ril'            => 1,
   'rio'            => 1,
   'rip'            => 1,
   'rmit'           => 1,
   'ro'             => 1,
   'rocher'         => 1,
   'rocks'          => 1,
   'rodeo'          => 1,
   'rogers'         => 1,
   'room'           => 1,
   'rs'             => 1,
   'rsvp'           => 1,
   'ru'             => 1,
   'rugby'          => 1,
   'ruhr'           => 1,
   'run'            => 1,
   'rw'             => 1,
   'rwe'            => 1,
   'ryukyu'         => 1,
   'sa'             => 1,
   'saarland'       => 1,
   'safe'           => 1,
   'safety'         => 1,
   'sakura'         => 1,
   'sale'           => 1,
   'salon'          => 1,
   'samsclub'       => 1,
   'samsung'        => 1,
   'sandvik'        => 1,
   'sandvikcoromant' => 1,
   'sanofi'         => 1,
   'sap'            => 1,
   'sapo'           => 1,
   'sarl'           => 1,
   'sas'            => 1,
   'save'           => 1,
   'saxo'           => 1,
   'sb'             => 1,
   'sbi'            => 1,
   'sbs'            => 1,
   'sc'             => 1,
   'sca'            => 1,
   'scb'            => 1,
   'schaeffler'     => 1,
   'schmidt'        => 1,
   'scholarships'   => 1,
   'school'         => 1,
   'schule'         => 1,
   'schwarz'        => 1,
   'science'        => 1,
   'scjohnson'      => 1,
   'scor'           => 1,
   'scot'           => 1,
   'sd'             => 1,
   'se'             => 1,
   'search'         => 1,
   'seat'           => 1,
   'secure'         => 1,
   'security'       => 1,
   'seek'           => 1,
   'select'         => 1,
   'sener'          => 1,
   'services'       => 1,
   'ses'            => 1,
   'seven'          => 1,
   'sew'            => 1,
   'sex'            => 1,
   'sexy'           => 1,
   'sfr'            => 1,
   'sg'             => 1,
   'sh'             => 1,
   'shangrila'      => 1,
   'sharp'          => 1,
   'shaw'           => 1,
   'shell'          => 1,
   'shia'           => 1,
   'shiksha'        => 1,
   'shoes'          => 1,
   'shop'           => 1,
   'shopping'       => 1,
   'shouji'         => 1,
   'show'           => 1,
   'showtime'       => 1,
   'shriram'        => 1,
   'si'             => 1,
   'silk'           => 1,
   'sina'           => 1,
   'singles'        => 1,
   'site'           => 1,
   'sj'             => 1,
   'sk'             => 1,
   'ski'            => 1,
   'skin'           => 1,
   'sky'            => 1,
   'skype'          => 1,
   'sl'             => 1,
   'sling'          => 1,
   'sm'             => 1,
   'smart'          => 1,
   'smile'          => 1,
   'sn'             => 1,
   'sncf'           => 1,
   'so'             => 1,
   'soccer'         => 1,
   'social'         => 1,
   'softbank'       => 1,
   'software'       => 1,
   'sohu'           => 1,
   'solar'          => 1,
   'solutions'      => 1,
   'song'           => 1,
   'sony'           => 1,
   'soy'            => 1,
   'space'          => 1,
   'spiegel'        => 1,
   'sport'          => 1,
   'spot'           => 1,
   'spreadbetting'  => 1,
   'sr'             => 1,
   'srl'            => 1,
   'srt'            => 1,
   'ss'             => 1,
   'st'             => 1,
   'stada'          => 1,
   'staples'        => 1,
   'star'           => 1,
   'starhub'        => 1,
   'statebank'      => 1,
   'statefarm'      => 1,
   'statoil'        => 1,
   'stc'            => 1,
   'stcgroup'       => 1,
   'stockholm'      => 1,
   'storage'        => 1,
   'store'          => 1,
   'stream'         => 1,
   'studio'         => 1,
   'study'          => 1,
   'style'          => 1,
   'su'             => 1,
   'sucks'          => 1,
   'supplies'       => 1,
   'supply'         => 1,
   'support'        => 1,
   'surf'           => 1,
   'surgery'        => 1,
   'suzuki'         => 1,
   'sv'             => 1,
   'swatch'         => 1,
   'swiftcover'     => 1,
   'swiss'          => 1,
   'sx'             => 1,
   'sy'             => 1,
   'sydney'         => 1,
   'symantec'       => 1,
   'systems'        => 1,
   'sz'             => 1,
   'tab'            => 1,
   'taipei'         => 1,
   'talk'           => 1,
   'taobao'         => 1,
   'target'         => 1,
   'tatamotors'     => 1,
   'tatar'          => 1,
   'tattoo'         => 1,
   'tax'            => 1,
   'taxi'           => 1,
   'tc'             => 1,
   'tci'            => 1,
   'td'             => 1,
   'tdk'            => 1,
   'team'           => 1,
   'tech'           => 1,
   'technology'     => 1,
   'tel'            => 1,
   'telecity'       => 1,
   'telefonica'     => 1,
   'temasek'        => 1,
   'tennis'         => 1,
   'teva'           => 1,
   'tf'             => 1,
   'tg'             => 1,
   'th'             => 1,
   'thd'            => 1,
   'theater'        => 1,
   'theatre'        => 1,
   'tiaa'           => 1,
   'tickets'        => 1,
   'tienda'         => 1,
   'tiffany'        => 1,
   'tips'           => 1,
   'tires'          => 1,
   'tirol'          => 1,
   'tj'             => 1,
   'tjmaxx'         => 1,
   'tjx'            => 1,
   'tk'             => 1,
   'tkmaxx'         => 1,
   'tl'             => 1,
   'tm'             => 1,
   'tmall'          => 1,
   'tn'             => 1,
   'to'             => 1,
   'today'          => 1,
   'tokyo'          => 1,
   'tools'          => 1,
   'top'            => 1,
   'toray'          => 1,
   'toshiba'        => 1,
   'total'          => 1,
   'tours'          => 1,
   'town'           => 1,
   'toyota'         => 1,
   'toys'           => 1,
   'tp'             => 1,
   'tr'             => 1,
   'trade'          => 1,
   'trading'        => 1,
   'training'       => 1,
   'travel'         => 1,
   'travelchannel'  => 1,
   'travelers'      => 1,
   'travelersinsurance' => 1,
   'trust'          => 1,
   'trv'            => 1,
   'tt'             => 1,
   'tube'           => 1,
   'tui'            => 1,
   'tunes'          => 1,
   'tushu'          => 1,
   'tv'             => 1,
   'tvs'            => 1,
   'tw'             => 1,
   'tz'             => 1,
   'ua'             => 1,
   'ubank'          => 1,
   'ubs'            => 1,
   'uconnect'       => 1,
   'ug'             => 1,
   'uk'             => 1,
   'um'             => 1,
   'unicom'         => 1,
   'university'     => 1,
   'uno'            => 1,
   'uol'            => 1,
   'ups'            => 1,
   'us'             => 1,
   'uy'             => 1,
   'uz'             => 1,
   'va'             => 1,
   'vacations'      => 1,
   'vana'           => 1,
   'vanguard'       => 1,
   'vc'             => 1,
   've'             => 1,
   'vegas'          => 1,
   'ventures'       => 1,
   'verisign'       => 1,
   'versicherung'   => 1,
   'vet'            => 1,
   'vg'             => 1,
   'vi'             => 1,
   'viajes'         => 1,
   'video'          => 1,
   'vig'            => 1,
   'viking'         => 1,
   'villas'         => 1,
   'vin'            => 1,
   'vip'            => 1,
   'virgin'         => 1,
   'visa'           => 1,
   'vision'         => 1,
   'vista'          => 1,
   'vistaprint'     => 1,
   'viva'           => 1,
   'vivo'           => 1,
   'vlaanderen'     => 1,
   'vn'             => 1,
   'vodka'          => 1,
   'volkswagen'     => 1,
   'volvo'          => 1,
   'vote'           => 1,
   'voting'         => 1,
   'voto'           => 1,
   'voyage'         => 1,
   'vu'             => 1,
   'vuelos'         => 1,
   'wales'          => 1,
   'walmart'        => 1,
   'walter'         => 1,
   'wang'           => 1,
   'wanggou'        => 1,
   'warman'         => 1,
   'watch'          => 1,
   'watches'        => 1,
   'weather'        => 1,
   'weatherchannel' => 1,
   'webcam'         => 1,
   'weber'          => 1,
   'website'        => 1,
   'wed'            => 1,
   'wedding'        => 1,
   'weibo'          => 1,
   'weir'           => 1,
   'wf'             => 1,
   'whoswho'        => 1,
   'wien'           => 1,
   'wiki'           => 1,
   'williamhill'    => 1,
   'win'            => 1,
   'windows'        => 1,
   'wine'           => 1,
   'winners'        => 1,
   'wme'            => 1,
   'wolterskluwer'  => 1,
   'woodside'       => 1,
   'work'           => 1,
   'works'          => 1,
   'world'          => 1,
   'wow'            => 1,
   'ws'             => 1,
   'wtc'            => 1,
   'wtf'            => 1,
   'xbox'           => 1,
   'xerox'          => 1,
   'xfinity'        => 1,
   'xihuan'         => 1,
   'xin'            => 1,
   'xperia'         => 1,
   'xxx'            => 1,
   'xyz'            => 1,
   'yachts'         => 1,
   'yahoo'          => 1,
   'yamaxun'        => 1,
   'yandex'         => 1,
   'ye'             => 1,
   'yodobashi'      => 1,
   'yoga'           => 1,
   'yokohama'       => 1,
   'you'            => 1,
   'youtube'        => 1,
   'yt'             => 1,
   'yun'            => 1,
   'za'             => 1,
   'zappos'         => 1,
   'zara'           => 1,
   'zero'           => 1,
   'zip'            => 1,
   'zippo'          => 1,
   'zm'             => 1,
   'zone'           => 1,
   'zuerich'        => 1,
   'zw'             => 1,
);

=head1 COPYRIGHT

Copyright (c) 1997, 1998, 2002, 2003 Jason Tibbitts for The Majordomo 
Development Group.  All rights reserved.

This program is free software; you can redistribute it and/or modify it
under the terms of the license detailed in the LICENSE file of the
Majordomo2 distribution.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the Majordomo2 LICENSE file for more
detailed information.

=cut

1;

