import struct
from argparse import ArgumentParser, SUPPRESS
from datetime import datetime, timedelta
from rich.table import Table
from rich import print_json, box
import simplejson as json
from libs.logging import Logger

def hail_mary(args, objects = []):
    date = datetime.now().strftime("%m_%d_%Y_%H_%M_%S")
    domain = objects[0].domain
    logger = Logger()
    filename = f'output/{domain}_{date}.txt'

    logger.info_special('Running all enumeration steps. This might take a while.\n')

    # LDAP STUFF
    _users = objects[0].users(args)
    print('\n', end='')
    _groups = objects[0].groups(args)
    print('\n', end='')
    _sid = objects[0].domain_sid(args)
    print('\n', end='')
    _asrep = objects[0].as_rep(args)
    print('\n', end='')
    _laps = objects[0].laps(False)
    print('\n', end='')
    _passwords = objects[0].search_for_passwords(args)
    print('\n', end='')

    # SMB STUFF
    _shares = objects[1].get_shares()
    print('\n', end='')

    # Password Policy
    _passpol = objects[2].dump_info()

    # Dump everything to a logfile

    with open(f'{filename}', 'w', encoding='latin-1') as f:
        f.write('--==SID==--\n\n')
        json.dump(_sid, f, indent=4, encoding='latin-1')

        f.write('\n\n--==USERS==--\n\n')
        json.dump(_users, f, indent=4, encoding='latin-1')

        f.write('\n\n--==GROUPS==--\n\n')
        json.dump(_groups, f, indent=4, encoding='latin-1')

        f.write('\n\n--==AS-REP==--\n\n')
        json.dump(_asrep, f, indent=4, encoding='latin-1')

        f.write('\n\n--==LAPS==--\n\n')
        json.dump(_laps, f, indent=4, encoding='latin-1')

        f.write('\n\n--==PASSWORDS==--\n\n')
        json.dump(_passwords, f, indent=4, encoding='latin-1')

        f.write('\n\n--==SHARES==--\n\n')
        json.dump(_shares, f, indent=4, encoding='latin-1')

        f.write('\n\n--==PASSWORD POLICY==--\n\n')
        json.dump(_passpol, f, indent=4, encoding='latin-1')

        f.write('\n')

    logger.info_special(f'Output written to: \033[1;36m{filename}\033[0m')

def outputfile(args, data):
    filename = args.output

    with open(filename, 'w', encoding='latin-1') as f:
        json.dump(data, f, indent=4, encoding='latin-1')

def pretty_print(data):
    table = Table(box=box.ASCII, show_lines=True)

    try:
        for col in data[0].keys():
            if col == 'distinguishedName':
                table.add_column(col, no_wrap=True)
            elif col == 'sAMAccountName' or col == 'name':
                table.add_column(col, style="green")
            else:
                table.add_column(col, no_wrap=False)

        for v in data:
            t = []
            for k,v in v.items():
                if isinstance(v, bytes):
                    t.append(v.decode('latin-1'))
                else:
                    t.append(v)
            table.add_row(*t)
    except KeyError:
        _temp = []
        for d in data.keys():
            table.add_column(d)
        for i in data.values():
            _temp.append(str(i))
        table.add_row(*_temp)
        return table
    return table

def json_encoding_callback(json):
    return json.decode('latin-1')

def convert_sid(binary):
    version = struct.unpack('B', binary[0:1])[0]
    # I do not know how to treat version != 1 (it does not exist yet)
    assert version == 1, version
    length = struct.unpack('B', binary[1:2])[0]
    authority = struct.unpack(b'>Q', b'\x00\x00' + binary[2:8])[0]
    string = 'S-%d-%d' % (version, authority)
    binary = binary[8:]
    assert len(binary) == 4 * length
    for i in range(length):
        value = struct.unpack('<L', binary[4*i:4*(i+1)])[0]
        string += '-%d' % value
    return string

def ldap2datetime(ts: float):
    if ts == 0:
        _timestamp = 'Never'
        return _timestamp
    else:
        _timestamp = datetime(1601, 1, 1) + timedelta(seconds=ts/10000000)
    return _timestamp.strftime("%m/%d/%Y %H:%M:%S")

def parse_arguments():
    parser = ArgumentParser(add_help=False)
    required_args = parser.add_argument_group('Required arguments')
    optional_args = parser.add_argument_group('Optional arguments')

    optional_args.add_argument(
        '-h',
        '--help',
        action='help',
        default=SUPPRESS,
        help='show this help message and exit'
    )

    optional_args.add_argument(
        '--passpol',
        action='store_true',
        help='Enumerate password policy'
    )

    optional_args.add_argument(
        '--shares',
        action='store_true',
        help='Enumerate SMB shares'
    )

    optional_args.add_argument(
        '--users',
        action='store_true',
        help='Dump all users in domain'
    )

    optional_args.add_argument(
        '--groups',
        action='store_true',
        help='Dump all groups in domain'
    )

    optional_args.add_argument(
        '--asrep',
        action='store_true',
        help='Enumerate AS REP roastable users'
    )

    optional_args.add_argument(
        '--sid',
        action='store_true',
        help='Enumerate domain SID'
    )

    optional_args.add_argument(
        '--check_laps',
        action='store_true',
        help='Check if LAPS is installed'
    )

    optional_args.add_argument(
        '--dump_laps',
        action='store_true',
        help='Dump ms-Mcs-AdmPwd for all computer objects'
    )

    optional_args.add_argument(
        '--passwords',
        action='store_true',
        help='Search for passwords stored in LDAP'
    )

    optional_args.add_argument(
        '--dump',
        action='store_true',
        help='Dump all LDAP objects'
    )

    optional_args.add_argument(
        '--query',
        help='Specify LDAP query manually'
    )

    optional_args.add_argument(
        '--filter',
        help='Filter LDAP output (attributes) using a comma separated string'
    )

    optional_args.add_argument(
        '--only_desc',
        action='store_true',
        help='Only show users with a description'
    )

    optional_args.add_argument(
        '--passwordspray',
        action='store_true',
        help='Can be used with --users in order to get a formatted list of usernames'
    )

    optional_args.add_argument(
        '--pretty',
        action='store_true',
        help='Pretty print the output'
    )

    optional_args.add_argument(
        '--output',
        help='Write results to file'
    )

    required_args.add_argument(
        '-i',
        '--ip',
        help='IP/Hostname to target',
        required=True
    )

    required_args.add_argument(
        '-u',
        '--username',
        help='Username',
        required=True
    )

    required_args.add_argument(
        '-p',
        '--password',
        help='Password',
        required=True
    )

    required_args.add_argument(
        '-d',
        '--domain',
        help='Domain',
        required=True
    )

    return parser.parse_args()