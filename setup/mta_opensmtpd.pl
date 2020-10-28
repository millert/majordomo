sub ask_opensmtpd {
  my $config = shift;
  my ($def, $msg);

  #---- Ask if alias/virtual user table should be maintained
  $msg = retr_msg('maintain_aliases', $lang, 'MTA' => 'OPENSMTPD');
  $def = $config->{'maintain_mtaconfig'} || 1;
  $config->{'maintain_mtaconfig'} = get_bool($msg, $def);

  # Technically we should ask about this, but I really doubt that anyone
  # ever changes it from the default.
  $config->{mta_separator} = '+';
}

sub setup_opensmtpd {};

sub setup_opensmtpd_domain {
  my($config, $dom) = @_;

  require "./setup/mta_sendmail.pl";
  setup_sendmail_domain($config, $dom);
}

=head1 COPYRIGHT

Copyright (c) 1999, 2002 Jason Tibbitts for The Majordomo Development
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
### cperl-label-offset:-1 ***
### indent-tabs-mode: nil ***
### End: ***
