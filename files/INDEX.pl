# List of default reply files and subjects to be installed in the GLOBAL filespace

$files =
  {
   # english generic files
   'en/ack_archive'                                   => ['Archived post to $LIST',                   'us-ascii', '7bit'],
   'en/ack_delay'                                     => ['Delayed post to $LIST',                    'us-ascii', '7bit'],
   'en/ack_denial'                                    => ['Denied post to $LIST',                     'us-ascii', '7bit'],
   'en/ack_rejection'                                 => ['Rejection of Majordomo Request "$COMMAND"','us-ascii', '7bit'],
   'en/ack_stall'                                     => ['Stalled post to $LIST',                    'us-ascii', '7bit'],
   'en/ack_success'                                   => ['Successful post to $LIST',                 'us-ascii', '7bit'],
   'en/ack_timeout'                                   => ['Timeout',                                  'us-ascii', '7bit'],
   'en/digest_preindex'                               => ['Index',                                    'us-ascii', '7bit'],
   'en/faq'                                           => ['Frequently Asked Questions',               'us-ascii', '7bit'],
   'en/file_not_found'                                => ['File not found',                           'us-ascii', '7bit'],
   'en/file_sent'                                     => ['File has been sent',                       'us-ascii', '7bit'],
   'en/info'                                          => ['List Information',                         'us-ascii', '7bit'],
   'en/inform'                                        => ['$UCOMMAND $LIST',                          'us-ascii', '7bit'],
   'en/intro'                                         => ['List Introductory Information',            'us-ascii', '7bit'],
   'en/new_list'                                      => ['$LIST mailing list created at $SITE',      'us-ascii', '7bit'],
   'en/new_password'                                  => ['New password at $SITE',                    'us-ascii', '7bit'],
   'en/registered'                                    => ['Welcome to $SITE',                         'us-ascii', '7bit'],
   'en/repl_chain'                                    => ['Default chained mailreply file',           'us-ascii', '7bit'],
   'en/repl_confcons'                                 => ['Default confirm+consult mailreply file',   'us-ascii', '7bit'],
   'en/repl_confirm'                                  => ['Default confirm mailreply file',           'us-ascii', '7bit'],
   'en/repl_confirm2'                                 => ['Default double-confirm mailreply file',    'us-ascii', '7bit'],
   'en/repl_consult'                                  => ['Default consult mailreply file',           'us-ascii', '7bit'],
   'en/repl_delay'                                    => ['Default delayed command reply file',       'us-ascii', '7bit'],
   'en/repl_deny'                                     => ['Default denial replyfile',                 'us-ascii', '7bit'],
   'en/repl_forward'                                  => ['Default forward replyfile',                'us-ascii', '7bit'],
   'en/repl_fulfill'                                  => ['Results from delayed command',             'us-ascii', '7bit'],
   'en/request_response'                              => ['Automated response from $REQUEST',         'us-ascii', '7bit'],
   'en/subscribe_to_self'                             => ['Attempt to subscribe $LIST to itself',     'us-ascii', '7bit'],
   'en/token_reject'                                  => ['Rejected token $TOKEN',                    'us-ascii', '7bit'],
   'en/token_reject_owner'                            => ['Token rejected by $REJECTER',              'us-ascii', '7bit'],
   'en/token_remind'                                  => ['$TOKEN : REMINDER from $LIST',             'us-ascii', '7bit'],
   'en/unknown_file'                                  => ['Unknown file',                             'us-ascii', '7bit'],
   'en/welcome'                                       => ['Welcome',                                  'us-ascii', '7bit'],

   # English configuration category files 
   'en/config/categories/access'                  => 
   ['Configuration category description.',
    'us-ascii', '7bit'],

   'en/config/categories/address'                 => 
   ['Configuration category description.',
    'us-ascii', '7bit'],

   'en/config/categories/archive'                 => 
   ['Configuration category description.',
    'us-ascii', '7bit'],

   'en/config/categories/bounce'                  => 
   ['Configuration category description.',
    'us-ascii', '7bit'],

   'en/config/categories/deliver'                 => 
   ['Configuration category description.',
    'us-ascii', '7bit'],

   'en/config/categories/lists'                   => 
   ['Configuration category description.',
    'us-ascii', '7bit'],

   'en/config/categories/miscellany'              => 
   ['Configuration category description.',
    'us-ascii', '7bit'],

   'en/config/categories/moderate'                => 
   ['Configuration category description.',
    'us-ascii', '7bit'],

   'en/config/categories/password'                => 
   ['Configuration category description.',
    'us-ascii', '7bit'],

   'en/config/categories/reply'                   => 
   ['Configuration category description.',
    'us-ascii', '7bit'],

   # English error formatting files 
   'en/error/invalid_command'                  => 
   ['Error format.  Warns that a command is invalid.',
    'us-ascii', '7bit'],

   'en/error/password_length'                  => 
   ['Error format.  Warns that a password is too short.',
    'us-ascii', '7bit'],

   'en/error/unregistered'                     => 
   ['Error format.  Warns that an address has not been registered.',
    'us-ascii', '7bit'],

   # English output formatting files (text)
   'en/format/text/configshow'                        => 
   ['Plain text configshow command format.  Shows var and value.',
    'us-ascii', '7bit'],

   'en/format/text/configshow_array'                  => 
   ['Plain text configshow command format.  Shows var and value.',
    'us-ascii', '7bit'],

   'en/format/text/configshow_categories'             => 
   ['Plain text configshow command format.  Shows var and value.',
    'us-ascii', '7bit'],

   'en/format/text/configshow_enum'                   => 
   ['Plain text configshow command format.  Shows var and value.',
    'us-ascii', '7bit'],

   'en/format/text/configshow_error'                  => 
   ['Plain text configshow command format.  Displays an error.',
    'us-ascii', '7bit'],

   'en/format/text/configshow_flags'                  => 
   ['Plain text configshow command format.  Shows var and value.',
    'us-ascii', '7bit'],

   'en/format/text/configshow_foot'                   => 
   ['Plain text configshow command format.  Shows foot.',
    'us-ascii', '7bit'],

   'en/format/text/configshow_head'                   => 
   ['Plain text configshow command format.  Shows head.',
    'us-ascii', '7bit'],

   'en/format/text/configshow_none'                   => 
   ['Plain text configshow command format.  No variables were found.',
    'us-ascii', '7bit'],

   'en/format/text/configshow_short'                  => 
   ['Plain text configshow command format.  Shows var and value.',
    'us-ascii', '7bit'],

   'en/format/text/lists'                             => 
   ['Plain text lists command format.  Shows list and description.',
    'us-ascii', '7bit'],

   'en/format/text/lists_category'                    => 
   ['Plain text lists command format.  Shows the name of a category.',
    'us-ascii', '7bit'],

   'en/format/text/lists_enhanced'                    => 
   ['Plain text lists command format.  Shows subscription details.',
    'us-ascii', '7bit'],

   'en/format/text/lists_error'                       => 
   ['Plain text lists command format.  Shows an error message.',
    'us-ascii', '7bit'],

   'en/format/text/lists_foot'                        => 
   ['Plain text lists command format.  Shows the number of lists.',
    'us-ascii', '7bit'],

   'en/format/text/lists_full'                        => 
   ['Plain text lists command format.  Shows digests and other data.',
    'us-ascii', '7bit'],

   'en/format/text/lists_head'                        => 
   ['Plain text lists command format.  Shows the site name.',
    'us-ascii', '7bit'],

   'en/format/text/lists_none'                        => 
   ['WWW user lists command format file.  Says that no lists were found.',
    'us-ascii', '7bit'],

   'en/format/text/show'                              => 
   ['Plain text show command format file.  Shows a table of data.',
    'us-ascii', '7bit'],

   'en/format/text/show_error'                        => 
   ['Plain text show command format file.  Displays an error.',
    'us-ascii', '7bit'],

   'en/format/text/show_foot'                         => 
   ['Plain text show command format file.  Displayed at the end of the output.',
    'us-ascii', '7bit'],

   'en/format/text/show_head'                         => 
   ['Plain text show command format file.  Displayed at the start of the output.',
    'us-ascii', '7bit'],

   'en/format/text/show_none'                         => 
   ['Plain text show command format file.  ' .
    'Shows data for an unregistered address.',
    'us-ascii', '7bit'],

   'en/format/text/showtokens'                        => 
   ['Plain text showtokens command format.  Displays tokens for one list.',
    'us-ascii', '7bit'],

   'en/format/text/showtokens_all'                    => 
   ['Plain text showtokens command format.  Displays tokens for all lists.',
    'us-ascii', '7bit'],

   'en/format/text/showtokens_all_data'               => 
   ['Plain text showtokens command format.  Displays one token.',
    'us-ascii', '7bit'],

   'en/format/text/showtokens_data'                   => 
   ['Plain text showtokens command format.  Displays one token.',
    'us-ascii', '7bit'],

   'en/format/text/showtokens_error'                  => 
   ['Plain text showtokens command format.  Displays an error.',
    'us-ascii', '7bit'],

   'en/format/text/showtokens_none'                   => 
   ['Plain text showtokens command format.  Warns that no tokens were found.',
    'us-ascii', '7bit'],

   'en/format/text/tokeninfo_error'                   => 
   ['Plain text tokeninfo command format.',
    'us-ascii', '7bit'],

   'en/format/text/tokeninfo_foot'                    => 
   ['Plain text tokeninfo command format.',
    'us-ascii', '7bit'],

   'en/format/text/tokeninfo_head'                    => 
   ['Plain text tokeninfo command format.',
    'us-ascii', '7bit'],

   'en/format/text/who'                               => 
   ['Plain text who command format.  Displays addresses.',
    'us-ascii', '7bit'],

   'en/format/text/who_error'                         => 
   ['Plain text who command format.  Displays an error message.',
    'us-ascii', '7bit'],

   'en/format/text/who_foot'                          => 
   ['Plain text who command format.  Displays the foot.',
    'us-ascii', '7bit'],

   'en/format/text/who_head'                          => 
   ['Plain text who command format.  Displays the head.',
    'us-ascii', '7bit'],

   'en/format/text/who_registry'                      => 
   ['Plain text who command format.  Displays addresses from the registry.',
    'us-ascii', '7bit'],

   'en/format/text/who_registry_foot'                 => 
   ['Plain text who command format.  Displays the foot.',
    'us-ascii', '7bit'],

   'en/format/text/who_registry_head'                 => 
   ['Plain text who command format.  Displays the head.',
    'us-ascii', '7bit'],

   # English output formatting files (mj_wwwadm)
   'en/format/wwwadm/command'                           => 
   ['WWW Admin command form format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/configshow'                        => 
   ['WWW Admin configshow command format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/configshow_array'                  => 
   ['WWW Admin configshow command format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/configshow_categories'             => 
   ['WWW Admin configshow command format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/configshow_enum'                   => 
   ['WWW Admin configshow command format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/configshow_error'                  => 
   ['WWW Admin configshow command format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/configshow_flags'                  => 
   ['WWW Admin configshow command format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/configshow_foot'                   => 
   ['WWW Admin configshow command format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/configshow_head'                   => 
   ['WWW Admin configshow command format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/configshow_none'                   => 
   ['WWW Admin configshow command format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/configshow_short'                  => 
   ['WWW Admin configshow command format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/foot'                              => 
   ['Footer for the WWW admin interface',
     'us-ascii', '7bit'],

   'en/format/wwwadm/head'                              => 
   ['Command form for the WWW admin interface',
     'us-ascii', '7bit'],

   'en/format/wwwadm/lists'                             => 
   ['WWW admin lists command format file.  Shows list and description.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/lists_category'                    => 
   ['WWW admin lists command format file.  Shows the name of a category.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/lists_enhanced'                    => 
   ['WWW admin lists command format file.  Shows subscription details.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/lists_error'                       => 
   ['WWW admin lists command format file.  Shows an error message.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/lists_foot'                        => 
   ['WWW admin lists command format file.  Ends a table of data.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/lists_full'                        => 
   ['WWW admin lists command format file.  Shows digests and other data.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/lists_head'                        => 
   ['WWW admin lists command format file.  Begins a table of data .',
    'us-ascii', '7bit'],

   'en/format/wwwadm/lists_none'                        => 
   ['WWW user lists command format file.  Says that no lists were found.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/login'                             => 
   ['WWW Admin login format file.',
     'us-ascii', '7bit'],

   'en/format/wwwadm/showtokens'                        => 
   ['WWW admin showtokens command format.  Displays tokens for one list.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/showtokens_all'                    => 
   ['WWW admin showtokens command format.  Displays tokens for all lists.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/showtokens_all_data'               => 
   ['WWW admin showtokens command format.  Displays one token.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/showtokens_data'                   => 
   ['WWW admin showtokens command format.  Displays one token.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/showtokens_error'                  => 
   ['WWW admin showtokens command format.  Displays an error.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/showtokens_foot'                   => 
   ['WWW admin showtokens command format.  Displays an error.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/showtokens_head'                   => 
   ['WWW admin showtokens command format.  Displays an error.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/showtokens_none'                   => 
   ['WWW admin showtokens command format.  Warns that no tokens were found.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/tokeninfo_error'                   => 
   ['WWW admin tokeninfo command format.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/tokeninfo_foot'                    => 
   ['WWW admin tokeninfo command format.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/tokeninfo_head'                    => 
   ['WWW admin tokeninfo command format.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/welcome'                           => 
   ['Introduction to the WWW admin interface',
    'us-ascii', '7bit'],

   'en/format/wwwadm/who'                               => 
   ['WWW admin who command format.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/who_error'                         => 
   ['WWW admin who command format.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/who_foot'                          => 
   ['WWW admin who command format.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/who_head'                          => 
   ['WWW admin who command format.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/who_registry'                      => 
   ['WWW admin who command format.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/who_registry_foot'                 => 
   ['WWW admin who command format.',
    'us-ascii', '7bit'],

   'en/format/wwwadm/who_registry_head'                 => 
   ['WWW admin who command format.',
    'us-ascii', '7bit'],

   # English output formatting files (mj_wwwusr)
   'en/format/wwwusr/error'                             => 
   ['WWW user error format file.  Displays an error.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/foot'                              => 
   ['WWW user footer file.  Displayed at the bottom of every page.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/head'                              => 
   ['WWW user header file.  Displayed at the top of every page.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/lists'                             => 
   ['WWW user lists command format file.  Shows list and description.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/lists_category'                    => 
   ['WWW user lists command format file.  Shows the name of a category.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/lists_enhanced'                    => 
   ['WWW user lists command format file.  Shows subscription details.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/lists_error'                       => 
   ['WWW user lists command format file.  Shows an error message.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/lists_foot'                        => 
   ['WWW user lists command format file.  Ends a table of data.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/lists_full'                        => 
   ['WWW user lists command format file.  Shows digests and other data.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/lists_head'                        => 
   ['WWW user lists command format file.  Begins a table of data.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/lists_none'                        => 
   ['WWW user lists command format file.  Says that no lists were found.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/login'                             => 
   ['WWW user lists command format file.  Prompt for address and password.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/show'                              => 
   ['WWW user show command format file.  Shows a table of data.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/show_error'                        => 
   ['WWW user show command format file.  Displays an error.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/show_foot'                         => 
   ['WWW user show command format file.  Displayed at the end of the output.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/show_head'                         => 
   ['WWW user show command format file.  Displayed at the start of the output.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/show_none'                         => 
   ['WWW user show command format file.  Shows data for an unregistered address.',
    'us-ascii', '7bit'],

   'en/format/wwwusr/welcome'                           => 
   ['WWW user introduction format file.  Displays a summary of features.',
    'us-ascii', '7bit'],

   # english help files
   'en/help/accept'                                   => ['detailed help for accept command',         'us-ascii', '7bit'],
   'en/help/access'                                   => ['help for a configset access_rules option', 'us-ascii', '7bit'],
   'en/help/admin'                                    => ['what administrators can do with majordomo','us-ascii', '7bit'],
   'en/help/admin_commands'                           => ['complete administrator command reference', 'us-ascii', '7bit'],
   'en/help/admin_passwords'                          => ['administrative reference for passwords',   'us-ascii', '7bit'],
   'en/help/advertise'                                => ['help for a configset access_rules option', 'us-ascii', '7bit'],
   'en/help/alias'                                    => ['detailed help for alias command',          'us-ascii', '7bit'],
   'en/help/aliasadd'                                 => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/aliasremove'                              => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/announce'                                 => ['detailed help for announce command',       'us-ascii', '7bit'],
   'en/help/approve'                                  => ['detailed help for approve command',        'us-ascii', '7bit'],
   'en/help/archive'                                  => ['detailed help for archive command',        'us-ascii', '7bit'],
   'en/help/auxiliary_list'                           => ['the purpose of auxiliary lists',           'us-ascii', '7bit'],
   'en/help/cancel'                                   => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/changeaddr'                               => ['detailed help for changeaddr command',     'us-ascii', '7bit'],
   'en/help/commands'                                 => ['complete user command reference',          'us-ascii', '7bit'],
   'en/help/config'                                   => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/configdef'                                => ['command alias help file',                  'us-ascii', '7bit'],
   'en/help/configdefault'                            => ['detailed help for configdefault command',  'us-ascii', '7bit'],
   'en/help/configedit'                               => ['detailed help for configedit command',     'us-ascii', '7bit'],
   'en/help/configset'                                => ['detailed  help for configset command',     'us-ascii', '7bit'],
   'en/help/configset_access_password_override'       => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_access_rules'                   => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_access_rules_variables'         => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_ack_attach_original'            => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_addr_allow_at_in_phrase'        => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_addr_allow_bang_paths'          => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_addr_allow_comments_after_route'=> ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_addr_allow_ending_dot'          => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_addr_limit_length'              => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_addr_require_fqdn'              => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_addr_strict_domain_check'       => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_addr_xforms'                    => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_admin_body'                     => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_admin_headers'                  => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_administrivia'                  => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_advertise'                      => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_advertise_subscribed'           => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_aliases'                        => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_allowed_classes'                => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_allowed_flags'                  => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_archive_access'                 => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_archive_dir'                    => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_archive_size'                   => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_archive_split'                  => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_archive_url'                    => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_attachment_rules'               => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_block_headers'                  => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_bounce_max_age'                 => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_bounce_max_count'               => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_bounce_probe_frequency'         => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_bounce_probe_pattern'           => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_bounce_recipients'              => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_bounce_rules'                   => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_category'                       => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_chunksize'                      => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_comments'                       => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_confirm_url'                    => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_database_backend'               => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_debug'                          => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_default_class'                  => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_default_flags'                  => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_default_language'               => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_default_lists_format'           => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_delete_headers'                 => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_delivery_rules'                 => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_description'                    => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_description_long'               => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_description_max_lines'          => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_digest_index_format'            => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_digest_issues'                  => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_digests'                        => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_dup_lifetime'                   => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_faq_access'                     => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_file_search'                    => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_file_share'                     => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_filedir'                        => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_get_access'                     => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_index_access'                   => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_info_access'                    => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_inform'                         => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_intro_access'                   => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_latchkey_lifetime'              => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_log_lifetime'                   => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_master_password'                => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_max_header_line_length'         => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_max_in_core'                    => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_max_mime_header_length'         => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_max_total_header_length'        => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_maxlength'                      => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_message_footer'                 => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_message_footer_frequency'       => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_message_fronter'                => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_message_fronter_frequency'      => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_message_headers'                => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_moderate'                       => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_moderator'                      => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_moderator_group'                => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_moderators'                     => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_noadvertise'                    => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_nonmember_flags'                => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_override_reply_to'              => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_owners'                         => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_password_min_length'            => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_passwords'                      => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_post_limits'                    => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_precedence'                     => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_purge_received'                 => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_quote_pattern'                  => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_reply_to'                       => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_request_answer'                 => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_resend_host'                    => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_restrict_post'                  => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_return_subject'                 => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_save_denial_checksums'          => ['The save_denial_checksums variable',       'us-ascii', '7bit'],
   'en/help/configset_sender'                         => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_sequence_number'                => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_session_lifetime'               => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_set_policy'                     => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_signature_separator'            => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_site_name'                      => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_subject_prefix'                 => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_subscribe_policy'               => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_sublists'                       => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_taboo_body'                     => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_taboo_headers'                  => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_tmpdir'                         => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_token_lifetime'                 => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_token_remind'                   => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_triggers'                       => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_unsubscribe_policy'             => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_welcome'                        => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_welcome_files'                  => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_whereami'                       => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_which_access'                   => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_who_access'                     => ['detailed help for configset listname',     'us-ascii', '7bit'],
   'en/help/configset_whoami'                         => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configset_whoami_owner'                   => ['detailed help for configset GLOBAL',       'us-ascii', '7bit'],
   'en/help/configshow'                               => ['detailed  help for configshow command',    'us-ascii', '7bit'],
   'en/help/createlist'                               => ['detailed help for createlist command',     'us-ascii', '7bit'],
   'en/help/default'                                  => ['detailed help for default command',        'us-ascii', '7bit'],
   'en/help/delay'                                    => ['how to delay a request',                   'us-ascii', '7bit'],
   'en/help/digest'                                   => ['detailed help for digest command',         'us-ascii', '7bit'],
   'en/help/end'                                      => ['detailed help for end command',            'us-ascii', '7bit'],
   'en/help/exit'                                     => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/faq'                                      => ['detailed help for faq command',            'us-ascii', '7bit'],
   'en/help/get'                                      => ['detailed help for get command',            'us-ascii', '7bit'],
   'en/help/help'                                     => ['default help file',                        'us-ascii', '7bit'],
   'en/help/index'                                    => ['detailed help for index command',          'us-ascii', '7bit'],
   'en/help/info'                                     => ['detailed help for info command',           'us-ascii', '7bit'],
   'en/help/intro'                                    => ['detailed help for intro command',          'us-ascii', '7bit'],
   'en/help/lists'                                    => ['detailed help for lists command',          'us-ascii', '7bit'],
   'en/help/man'                                      => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/mj_shell'                                 => ['man page for mj_shell',                    'us-ascii', '7bit'],
   'en/help/mkdigest'                                 => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/newconfig'                                => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/newfaq'                                   => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/newinfo'                                  => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/newintro'                                 => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/overview'                                 => ['what a user can do with majordomo',        'us-ascii', '7bit'],
   'en/help/owner'                                    => ['default help file for non-user command',   'us-ascii', '7bit'],
   'en/help/password'                                 => ['detailed help for password command',       'us-ascii', '7bit'],
   'en/help/patterns'                                 => ['help on patterns and regular expressions', 'us-ascii', '7bit'],
   'en/help/post'                                     => ['detailed help for post command',           'us-ascii', '7bit'],
   'en/help/put'                                      => ['detailed help for put command',            'us-ascii', '7bit'],
   'en/help/quit'                                     => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/register'                                 => ['detailed help for register command',       'us-ascii', '7bit'],
   'en/help/reject'                                   => ['detailed help for reject command',         'us-ascii', '7bit'],
   'en/help/rekey'                                    => ['detailed help for rekey command',          'us-ascii', '7bit'],
   'en/help/remove'                                   => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/report'                                   => ['detailed help for report command',         'us-ascii', '7bit'],
   'en/help/request_response'                         => ['default help file for non-user command',   'us-ascii', '7bit'],
   'en/help/sessioninfo'                              => ['detailed help for sessioninfo command',    'us-ascii', '7bit'],
   'en/help/set'                                      => ['detailed help for set command',            'us-ascii', '7bit'],
   'en/help/show'                                     => ['detailed help for show command',           'us-ascii', '7bit'],
   'en/help/showtokens'                               => ['detailed help for showtokens command',     'us-ascii', '7bit'],
   'en/help/signoff'                                  => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/stop'                                     => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/sub'                                      => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/subscribe'                                => ['detailed help for subscribe command',      'us-ascii', '7bit'],
   'en/help/times'                                    => ['exhaustive description of Mj2 time specs', 'us-ascii', '7bit'],
   'en/help/tokeninfo'                                => ['detailed help for tokeninfo command',      'us-ascii', '7bit'],
   'en/help/topics'                                   => ['exhaustive list of help commands',         'us-ascii', '7bit'],
   'en/help/trigger'                                  => ['default help file for non-user command',   'us-ascii', '7bit'],
   'en/help/unalias'                                  => ['detailed help for unalias command',        'us-ascii', '7bit'],
   'en/help/unknowntopic'                             => ['error message for help xxx',               'us-ascii', '7bit'],
   'en/help/unregister'                               => ['detailed help for unregister command',     'us-ascii', '7bit'],
   'en/help/unsub'                                    => ['alias help file',                          'us-ascii', '7bit'],
   'en/help/unsubscribe'                              => ['detailed help for unsubscribe command',    'us-ascii', '7bit'],
   'en/help/variables'                                => ['detailed help about put file variables',   'us-ascii', '7bit'],
   'en/help/which'                                    => ['detailed help for which command',          'us-ascii', '7bit'],
   'en/help/who'                                      => ['detailed help for who command',            'us-ascii', '7bit'],

   # english configuration variable descriptions, which are in help files via $INCLUDE
   'en/config/access_password_override'        => ['The access_password_override variable',        'us-ascii', '7bit'],
   'en/config/access_rules'                    => ['The access_rules variable',                    'us-ascii', '7bit'],
   'en/config/ack_attach_original'             => ['The ack_attach_original variable',             'us-ascii', '7bit'],
   'en/config/addr_allow_at_in_phrase'         => ['The addr_allow_at_in_phrase variable',         'us-ascii', '7bit'],
   'en/config/addr_allow_bang_paths'           => ['The addr_allow_bang_paths variable',           'us-ascii', '7bit'],
   'en/config/addr_allow_comments_after_route' => ['The addr_allow_comments_after_route variable', 'us-ascii', '7bit'],
   'en/config/addr_allow_ending_dot'           => ['The addr_allow_ending_dot variable',           'us-ascii', '7bit'],
   'en/config/addr_limit_length'               => ['The addr_limit_length variable',               'us-ascii', '7bit'],
   'en/config/addr_require_fqdn'               => ['The addr_require_fqdn variable',               'us-ascii', '7bit'],
   'en/config/addr_strict_domain_check'        => ['The addr_strict_domain_check variable',        'us-ascii', '7bit'],
   'en/config/addr_xforms'                     => ['The addr_xforms variable',                     'us-ascii', '7bit'],
   'en/config/admin_body'                      => ['The admin_body variable',                      'us-ascii', '7bit'],
   'en/config/admin_headers'                   => ['The admin_headers variable',                   'us-ascii', '7bit'],
   'en/config/administrivia'                   => ['The administrivia variable',                   'us-ascii', '7bit'],
   'en/config/advertise'                       => ['The advertise variable',                       'us-ascii', '7bit'],
   'en/config/advertise_subscribed'            => ['The advertise_subscribed variable',            'us-ascii', '7bit'],
   'en/config/aliases'                         => ['The aliases variable',                         'us-ascii', '7bit'],
   'en/config/allowed_classes'                 => ['The allowed_classes variable',                 'us-ascii', '7bit'],
   'en/config/allowed_flags'                   => ['The allowed_flags variable',                   'us-ascii', '7bit'],
   'en/config/archive_access'                  => ['The archive_access variable',                  'us-ascii', '7bit'],
   'en/config/archive_dir'                     => ['The archive_dir variable',                     'us-ascii', '7bit'],
   'en/config/archive_size'                    => ['The archive_size variable',                    'us-ascii', '7bit'],
   'en/config/archive_split'                   => ['The archive_split variable',                   'us-ascii', '7bit'],
   'en/config/archive_url'                     => ['The archive_url variable',                     'us-ascii', '7bit'],
   'en/config/attachment_rules'                => ['The attachment_rules variable',                'us-ascii', '7bit'],
   'en/config/block_headers'                   => ['The block_headers variable',                   'us-ascii', '7bit'],
   'en/config/bounce_max_age'                  => ['The bounce_max_age variable',                  'us-ascii', '7bit'],
   'en/config/bounce_max_count'                => ['The bounce_max_count variable',                'us-ascii', '7bit'],
   'en/config/bounce_probe_frequency'          => ['The bounce_probe_frequency variable',          'us-ascii', '7bit'],
   'en/config/bounce_probe_pattern'            => ['The bounce_probe_pattern variable',            'us-ascii', '7bit'],
   'en/config/bounce_recipients'               => ['The bounce_recipients variable',               'us-ascii', '7bit'],
   'en/config/bounce_rules'                    => ['The bounce_rules variable',                    'us-ascii', '7bit'],
   'en/config/category'                        => ['The category variable',                        'us-ascii', '7bit'],
   'en/config/chunksize'                       => ['The chunksize variable',                       'us-ascii', '7bit'],
   'en/config/comments'                        => ['The comments variable',                        'us-ascii', '7bit'],
   'en/config/confirm_url'                     => ['The confirm_url variable',                     'us-ascii', '7bit'],
   'en/config/database_backend'                => ['The database_backend variable',                'us-ascii', '7bit'],
   'en/config/debug'                           => ['The debug variable',                           'us-ascii', '7bit'],
   'en/config/default_class'                   => ['The default_class variable',                   'us-ascii', '7bit'],
   'en/config/default_flags'                   => ['The default_flags variable',                   'us-ascii', '7bit'],
   'en/config/default_language'                => ['The default_language variable',                'us-ascii', '7bit'],
   'en/config/default_lists_format'            => ['The default_lists_format variable',            'us-ascii', '7bit'],
   'en/config/delete_headers'                  => ['The delete_headers variable',                  'us-ascii', '7bit'],
   'en/config/delivery_rules'                  => ['The delivery_rules variable',                  'us-ascii', '7bit'],
   'en/config/description'                     => ['The description variable',                     'us-ascii', '7bit'],
   'en/config/description_long'                => ['The description_long variable',                'us-ascii', '7bit'],
   'en/config/description_max_lines'           => ['The description_max_lines variable',           'us-ascii', '7bit'],
   'en/config/digest_index_format'             => ['The digest_index_format variable',             'us-ascii', '7bit'],
   'en/config/digest_issues'                   => ['The digest_issues variable',                   'us-ascii', '7bit'],
   'en/config/digests'                         => ['The digests variable',                         'us-ascii', '7bit'],
   'en/config/dup_lifetime'                    => ['The dup_lifetime variable',                    'us-ascii', '7bit'],
   'en/config/faq_access'                      => ['The faq_access variable',                      'us-ascii', '7bit'],
   'en/config/file_search'                     => ['The file_search variable',                     'us-ascii', '7bit'],
   'en/config/file_share'                      => ['The file_share variable',                      'us-ascii', '7bit'],
   'en/config/filedir'                         => ['The filedir variable',                         'us-ascii', '7bit'],
   'en/config/get_access'                      => ['The get_access variable',                      'us-ascii', '7bit'],
   'en/config/index_access'                    => ['The index_access variable',                    'us-ascii', '7bit'],
   'en/config/info_access'                     => ['The info_access variable',                     'us-ascii', '7bit'],
   'en/config/inform'                          => ['The inform variable',                          'us-ascii', '7bit'],
   'en/config/intro_access'                    => ['The intro_access variable',                    'us-ascii', '7bit'],
   'en/config/latchkey_lifetime'               => ['The latchkey_lifetime variable',               'us-ascii', '7bit'],
   'en/config/log_lifetime'                    => ['The log_lifetime variable',                    'us-ascii', '7bit'],
   'en/config/master_password'                 => ['The master_password variable',                 'us-ascii', '7bit'],
   'en/config/max_header_line_length'          => ['The max_header_line_length variable',          'us-ascii', '7bit'],
   'en/config/max_in_core'                     => ['The max_in_core variable',                     'us-ascii', '7bit'],
   'en/config/max_mime_header_length'          => ['The max_mime_header_length variable',          'us-ascii', '7bit'],
   'en/config/max_total_header_length'         => ['The max_total_header_length variable',         'us-ascii', '7bit'],
   'en/config/maxlength'                       => ['The maxlength variable',                       'us-ascii', '7bit'],
   'en/config/message_footer'                  => ['The message_footer variable',                  'us-ascii', '7bit'],
   'en/config/message_footer_frequency'        => ['The message_footer_frequency variable',        'us-ascii', '7bit'],
   'en/config/message_fronter'                 => ['The message_fronter variable',                 'us-ascii', '7bit'],
   'en/config/message_fronter_frequency'       => ['The message_fronter_frequency variable',       'us-ascii', '7bit'],
   'en/config/message_headers'                 => ['The message_headers variable',                 'us-ascii', '7bit'],
   'en/config/moderate'                        => ['The moderate variable',                        'us-ascii', '7bit'],
   'en/config/moderator'                       => ['The moderator variable',                       'us-ascii', '7bit'],
   'en/config/moderator_group'                 => ['The moderator_group variable',                 'us-ascii', '7bit'],
   'en/config/moderators'                      => ['The moderators variable',                      'us-ascii', '7bit'],
   'en/config/noadvertise'                     => ['The noadvertise variable',                     'us-ascii', '7bit'],
   'en/config/nonmember_flags'                 => ['The nonmember_flags variable',                 'us-ascii', '7bit'],
   'en/config/override_reply_to'               => ['The override_reply_to variable',               'us-ascii', '7bit'],
   'en/config/owners'                          => ['The owners variable',                          'us-ascii', '7bit'],
   'en/config/password_min_length'             => ['The password_min_length variable',             'us-ascii', '7bit'],
   'en/config/passwords'                       => ['The passwords variable',                       'us-ascii', '7bit'],
   'en/config/post_limits'                     => ['The post_limits variable',                     'us-ascii', '7bit'],
   'en/config/precedence'                      => ['The precedence variable',                      'us-ascii', '7bit'],
   'en/config/purge_received'                  => ['The purge_received variable',                  'us-ascii', '7bit'],
   'en/config/quote_pattern'                   => ['The quote_pattern variable',                   'us-ascii', '7bit'],
   'en/config/reply_to'                        => ['The reply_to variable',                        'us-ascii', '7bit'],
   'en/config/request_answer'                  => ['The request_answer variable',                  'us-ascii', '7bit'],
   'en/config/resend_host'                     => ['The resend_host variable',                     'us-ascii', '7bit'],
   'en/config/restrict_post'                   => ['The restrict_post variable',                   'us-ascii', '7bit'],
   'en/config/return_subject'                  => ['The return_subject variable',                  'us-ascii', '7bit'],
   'en/config/save_denial_checksums'           => ['The save_denial_checksums variable',           'us-ascii', '7bit'],
   'en/config/sender'                          => ['The sender variable',                          'us-ascii', '7bit'],
   'en/config/sequence_number'                 => ['The sequence_number variable',                 'us-ascii', '7bit'],
   'en/config/session_lifetime'                => ['The session_lifetime variable',                'us-ascii', '7bit'],
   'en/config/set_policy'                      => ['The set_policy variable',                      'us-ascii', '7bit'],
   'en/config/signature_separator'             => ['The signature_separator variable',             'us-ascii', '7bit'],
   'en/config/site_name'                       => ['The site_name variable',                       'us-ascii', '7bit'],
   'en/config/subject_prefix'                  => ['The subject_prefix variable',                  'us-ascii', '7bit'],
   'en/config/sublists'                        => ['The sublists variable',                        'us-ascii', '7bit'],
   'en/config/subscribe_policy'                => ['The subscribe_policy variable',                'us-ascii', '7bit'],
   'en/config/taboo_body'                      => ['The taboo_body variable',                      'us-ascii', '7bit'],
   'en/config/taboo_headers'                   => ['The taboo_headers variable',                   'us-ascii', '7bit'],
   'en/config/tmpdir'                          => ['The tmpdir variable',                          'us-ascii', '7bit'],
   'en/config/token_lifetime'                  => ['The token_lifetime variable',                  'us-ascii', '7bit'],
   'en/config/token_remind'                    => ['The token_remind variable',                    'us-ascii', '7bit'],
   'en/config/triggers'                        => ['The triggers variable',                        'us-ascii', '7bit'],
   'en/config/unsubscribe_policy'              => ['The unsubscribe_policy variable',              'us-ascii', '7bit'],
   'en/config/welcome'                         => ['The welcome variable',                         'us-ascii', '7bit'],
   'en/config/welcome_files'                   => ['The welcome_files variable',                   'us-ascii', '7bit'],
   'en/config/whereami'                        => ['The whereami variable',                        'us-ascii', '7bit'],
   'en/config/which_access'                    => ['The which_access variable',                    'us-ascii', '7bit'],
   'en/config/who_access'                      => ['The who_access variable',                      'us-ascii', '7bit'],
   'en/config/whoami'                          => ['The whoami variable',                          'us-ascii', '7bit'],
   'en/config/whoami_owner'                    => ['The whoami_owner variable',                    'us-ascii', '7bit'],

   # German
   'de/ack_denial'              => 'Denied post to $LIST',
   'de/ack_rejection'           => 'Rejection',
   'de/ack_stall'               => 'Stalled post to $LIST',
   'de/ack_success'             => 'Success',
   'de/ack_timeout'             => 'Timeout',
   'de/faq'                     => 'Default faq reply',
   'de/file_sent'               => 'File has been sent',
   'de/info'                    => 'Info',
   'de/intro'                   => 'Intro',
   'de/welcome'                 => 'Welcome',
#   'de/registered'              => 'Welcome to $SITE',
   'de/inform'                  => '$UCOMMAND $LIST',
   'de/repl_consult'            => 'Default consult mailreply file',
   'de/repl_confirm'            => 'Default confirm mailreply file',
   'de/repl_confcons'           => 'Default confirm+consult mailreply file',
   'de/repl_chain'              => 'Default chained mailreply file',
   'de/repl_deny'               => 'Default denial replyfile',
   'de/repl_forward'            => 'Default forward replyfile',
#   'de/request_response'        => 'Automated response from $REQUEST',
   'de/subscribe_to_self'       => 'Attempt to subscribe $LIST to itself',
   'de/token_reject'            => 'Rejected token $TOKEN',
   'de/token_reject_owner'      => 'Token rejected by $REJECTER',
   'de/token_remind'            => '$TOKEN : REMINDER from $LIST',
#    'de/help/default'            => 'Default help file',
#    'de/help/commands'           => 'Overview of available commands',
#    'de/help/parser'             => 'Information about the text parser',
#    'de/help/subscribe'          => 'Help on subscribing',
#    'de/help/topics'             => 'Available help topics',
#    'de/help/admin_commands'     => 'Overview of available administrative commands',
#    'de/help/admin_configuration'=> 'Overview of configuration variables and methods',
#    'de/help/admin_passwords'    => 'Information on Majordomo security and passwords',

   # Informal German
   'de/informal/ack_denial'              => 'Denial',
   'de/informal/ack_rejection'           => 'Rejection',
   'de/informal/ack_stall'               => 'Stall',
   'de/informal/ack_success'             => 'Success',
   'de/informal/ack_timeout'             => 'Timeout',
   'de/informal/faq'                     => 'Default faq reply',
   'de/informal/file_sent'               => 'File has been sent',
   'de/informal/info'                    => 'Info',
   'de/informal/intro'                   => 'Intro',
   'de/informal/welcome'                 => 'Welcome',
#   'de/informal/registered'              => 'Welcome to $SITE',
   'de/informal/inform'                  => '$UCOMMAND $LIST',
   'de/informal/repl_consult'            => 'Default consult mailreply file',
   'de/informal/repl_confirm'            => 'Default confirm mailreply file',
   'de/informal/repl_confcons'           => 'Default confirm+consult mailreply file',
   'de/informal/repl_chain'              => 'Default chained mailreply file',
   'de/informal/repl_deny'               => 'Default denial replyfile',
   'de/informal/repl_forward'            => 'Default forward replyfile',
#   'de/informal/request_response'        => 'Automated response from $REQUEST',
   'de/informal/subscribe_to_self'       => 'Attempt to subscribe $LIST to itself',
   'de/informal/token_reject'            => 'Rejected token $TOKEN',
   'de/informal/token_reject_owner'      => 'Token rejected by $REJECTER',
   'de/informal/token_remind'            => '$TOKEN : REMINDER from $LIST',
#    'de/informal/help/default'            => 'Default help file',
#    'de/informal/help/commands'           => 'Overview of available commands',
#    'de/informal/help/parser'             => 'Information about the text parser',
#    'de/informal/help/subscribe'          => 'Help on subscribing',
#    'de/informal/help/topics'             => 'Available help topics',
#    'de/informal/help/admin_commands'     => 'Overview of available administrative commands',
#    'de/informal/help/admin_configuration'=> 'Overview of configuration variables and methods',
#    'de/informal/help/admin_passwords'    => 'Information on Majordomo security and passwords',

  };

# Files that are conditional on a working web server
if ($indexflags & 1) {
  $files->{'en/confirm'} = ['$TOKEN : CONFIRM from $LIST ($COMMAND)', 'us-ascii', '7bit'];
  $files->{'en/consult'} = ['$TOKEN : CONSULT from $LIST ($COMMAND)', 'us-ascii', '7bit'];
  $files->{'en/delay'}   = ['$TOKEN : Delayed Command ($COMMAND)', 'us-ascii', '7bit'];

  $files->{'de/confirm'} = '$TOKEN : CONFIRM from $LIST';
  $files->{'de/consult'} = '$TOKEN : CONSULT from $LIST';

  $files->{'de/informal/confirm'} = '$TOKEN : CONFIRM from $LIST';
  $files->{'de/informal/consult'} = '$TOKEN : CONSULT from $LIST';
}
else {
  $files->{'en/confirm'} = ['$TOKEN : CONFIRM from $LIST ($COMMAND)', 'us-ascii', '7bit', 'en/confirm_noweb'];
  $files->{'en/consult'} = ['$TOKEN : CONSULT from $LIST ($COMMAND)', 'us-ascii', '7bit', 'en/consult_noweb'];
  $files->{'en/delay'}   = ['$TOKEN : Delayed Command ($COMMAND)', 'us-ascii', '7bit', 'en/delay_noweb'];

  $files->{'de/confirm'} = ['$TOKEN : CONFIRM from $LIST', 'ISO-8859-1', '8bit', 'de/confirm_noweb'];
  $files->{'de/consult'} = ['$TOKEN : CONSULT from $LIST', 'ISO-8859-1', '8bit', 'de/consult_noweb'];

  $files->{'de/informal/confirm'} = ['$TOKEN : CONFIRM from $LIST', 'ISO-8859-1', '8bit', 'de/informal/confirm_noweb'];
  $files->{'de/informal/consult'} = ['$TOKEN : CONSULT from $LIST', 'ISO-8859-1', '8bit', 'de/informal/consult_noweb'];
}

# Directories; no longer useful but left here in case they are subsequently
# used, perhaps to fake a filespace to make the index command work better.
$dirs =
  ['stock'                  => 'Majordomo-supplied files',
   'stock/en'               => 'English',
   'stock/en/help'          => 'English Help files',
   'stock/de'               => 'German',
   'stock/de/help'          => 'German Help Files',
   'stock/de/informal'      => 'Informal German',
   'stock/de/informal/help' => 'Informal German Help Files',
  ];

[$files, $dirs];
