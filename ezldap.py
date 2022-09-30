import sys
from argparse import ArgumentParser, SUPPRESS
from libs.smb.password_policy import PasswordPolicy
from libs.ldap.ldap import LdapDump
from helpers.helpers import parse_arguments, json_encoding_callback, pretty_print
from rich.console import Console
from rich import print_json
from helpers.banner import show_banner
from libs.smb.shares import SMBShares
from helpers.helpers import hail_mary

show_banner()

args = parse_arguments()
console = Console()

if len(sys.argv) > 9:
    ldap_obj = LdapDump(args)
    
    if args.passpol:
        pass_pol = PasswordPolicy(args).dump_info()
        if args.pretty:
            console.print(pretty_print(pass_pol))
        else:
            print_json(data=pass_pol)

    elif args.shares:
        smb_obj = SMBShares(args)
        shares = smb_obj.get_shares()
        if shares is False: sys.exit(-1)

        if args.pretty:
            console.print(pretty_print(shares))
        else:
            print_json(data=shares)

    elif args.users:
        ldap_users = ldap_obj.users(args)
        if ldap_users is False: sys.exit(-1)

        if args.passwordspray:
            print('\n'.join(ldap_users))
        else:
            if args.pretty:
                console.print(pretty_print(ldap_users))
            else:
                print_json(data=ldap_users)

    elif args.passwords:
        ldap_passwords = ldap_obj.search_for_passwords(args)
        if ldap_passwords is False: sys.exit(-1)

        if args.pretty:
            console.print(pretty_print(ldap_passwords))
        else:
            print_json(data=ldap_passwords, default=json_encoding_callback)

    elif args.groups:
        ldap_groups = ldap_obj.groups(args)
        if ldap_groups is False: sys.exit(-1)

        if args.pretty:
            console.print(pretty_print(ldap_groups))
        else:
            print_json(data=ldap_groups, default=json_encoding_callback)

    elif args.asrep:
        as_rep_users = ldap_obj.as_rep(args)
        if as_rep_users is False: sys.exit(-1)

        if args.pretty:
            console.print(pretty_print(as_rep_users))
        else:
            print_json(data=as_rep_users)

    elif args.sid:
        domain_sid = ldap_obj.domain_sid(args)
        if domain_sid is False: sys.exit(-1)

        if args.pretty:
            console.print(pretty_print(domain_sid))
        else:
            print_json(data=domain_sid)

    elif args.query:
        domain_sid = ldap_obj.raw_query(args)
        if domain_sid is False: sys.exit(-1)

        print_json(data=domain_sid, default=json_encoding_callback)

    elif args.check_laps:
        laps = ldap_obj.laps()
        if laps is False: sys.exit(-1)

        print_json(data=laps, default=json_encoding_callback)

    elif args.dump_laps:
        laps = ldap_obj.laps(dump=True, filter=args.filter)
        if laps is False: sys.exit(-1)

        if args.pretty:
            console.print(pretty_print(laps))
        else:
            print_json(data=laps, default=json_encoding_callback)

    elif args.dump:
        raw_dump = ldap_obj.dump_all(args)
        if raw_dump is False: sys.exit(-1)

        print_json(data=raw_dump, default=json_encoding_callback)

else:
    hail_mary(args, [LdapDump(args), SMBShares(args), PasswordPolicy(args)])
