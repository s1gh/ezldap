import ldap
import sys
import re
import json
from datetime import datetime
from tkinter import E
from rich.text import Text
from helpers.helpers import ldap2datetime, convert_sid, outputfile
from libs.logging import Logger

UF_ACCOUNTDISABLE = 2
UF_SERVER_TRUST_ACCOUNT = 8192
UF_DONT_REQUIRE_PREAUTH = 4194304

class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('latin-1')
        return json.JSONEncoder.default(self, obj)

class LdapDump:
    def __init__(self, args):
        self.logger = Logger()
        self.host = args.ip
        self.user = args.username
        self.passwd = args.password
        self.domain = args.domain if args.domain != '' else self._determine_domain_name()
        self.ldap_conn = self._setup_ldap_connection()
        self.base = self._base_builder(self.domain)

    def raw_query(self, args):
        if args.filter is None:
            att = None
        else:
            att = args.filter.split(',')

        res = self._ldap_query(args.query, att)

        if args.output:
            outputfile(args, res)

        return res

    def dump_all(self, args):
        crit = "(objectclass=*)"
        att = ["*", "+"]
        res = self._ldap_query(crit, att)

        if args.output:
            outputfile(args, res)

        return res

    def search_for_passwords(self, args):
        self.logger.info('Searching LDAP for passwords...')

        crit = "(objectclass=*)"
        att = ["*", "+"]
        search_pattern = re.compile(r'\b(?!\bbadPwdCount|pwdLastSet|badPasswordTime|pwdProperties|pwdHistoryLength|maxPwdAge|minPwdAge|minPwdLength)(.*pwd.*|.?passwd.|.*pass.*)', re.IGNORECASE)
        res = self._ldap_query(crit, att)
        false_positives = [
                'sAMAccountName',
                'cn',
                'memberOf',
                'name',
                'distinguishedName',
                'objectCategory',
                'objectClass',
                'ipsecName',
                'Permit unsecure ICMP packets to pass through.',
                'Permit unsecured IP packets to pass through.',
                'Members in this group can have their passwords replicated to all read-only domain controllers in the domain',
                'Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain',
                'msDS-ExpirePasswordsOnSmartCardOnlyAccounts',
                'ms-Mcs-AdmPwdExpirationTime',
                'Local Administrator Password Solution',
                'msExchBypassAudit'
                ]
        search_results = []

        if not res:
            self.logger.error('Enumerating passwords was unsuccessful!')
            return False

        for list_item in res:
            for k,v in list_item.items():
                att_key = search_pattern.search(k)

                if att_key is not None and k.strip() not in false_positives:
                    if isinstance(v, list):
                        for i in v:
                            search_results.append({k:i})
                    else:
                        search_results.append({k:v})

                if isinstance(v, list):
                    for attribute_value in v:
                        att_val = search_pattern.search(attribute_value.decode('latin-1'))
                else:
                    att_val = search_pattern.search(v)

                if att_val is not None:
                    if k.strip() not in false_positives and att_val.group(0) not in false_positives:
                        if isinstance(att_val.group(0), list):
                            print('yes')
                        search_results.append({k:att_val.group(0)})

        
        if len(search_results) > 0:
            self.logger.success('We might have found a total of {} passwords!'.format(len(search_results)))
            return search_results
        else:
            self.logger.error('We did not find any passwords :(')
            return False

    def laps(self, dump=False, filter=None):
        if dump:
            self.logger.info('Verifying if we can read sensitive LAPS attributes...')
            
            crit = "(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))"

            if filter is None:
                att = ['ms-Mcs-AdmPwd', 'dNSHostName', 'ms-Mcs-AdmPwdExpirationTime']
            else:
                att = filter.split(',')

            result = self._ldap_query(crit, att)
            
            if result is False:
                return False

            result = self._format_ldap_results(att, result)

            if len(result) > 0:
                if 'ms-Mcs-AdmPwd' in result[0].keys():
                    self.logger.success('We can read the ms-Mcs-AdmPwd attribute! Dumping LAPS passwords now...')
                else:
                    self.logger.error('We could not read the ms-Mcs-AdmPwd attribute :(')
                    return False
            else:
                self.logger.error('We could not read the ms-Mcs-AdmPwd attribute :(')
                return False

            for p in result:
                try:
                    p['ms-Mcs-AdmPwdExpirationTime'] = ldap2datetime(float(p['ms-Mcs-AdmPwdExpirationTime']))
                except KeyError:
                    pass
        else:
            self.logger.info('Enumerating LAPS (Local Administrator Password Soulution)...')
            try:
                base = f'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,{self.base}'
                result = self.ldap_conn.search_s(base, ldap.SCOPE_SUBTREE, None, None)
            except ldap.NO_SUCH_OBJECT:
                self.logger.success('Could not find any attributes related to LAPS. Not installed?')
                return False
            except ldap.OPERATIONS_ERROR as err:
                self.logger.error('In order to perform this operation a successful bind must be completed on the connection.')
                self.logger.error('Enumerating LAPS was unsuccessful!')
                return False
            else:
                self.logger.error('Found LAPS related attributes. LAPS seems to be installed!')
        return result

    def domain_sid(self, args):
        self.logger.info('Enumerating the domain SID...')

        try:
            crit = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d))" % UF_SERVER_TRUST_ACCOUNT
            att = ['sAMAccountName', 'objectSid']
            res = self._ldap_query(crit, att)
            res = self._format_ldap_results(att, res)
            res[0]['objectSid'] = convert_sid(res[0]['objectSid'].encode('latin-1')).rsplit('-', 1)[0]
        except Exception:
            self.logger.error('Enumerating domain SID was unsuccessful!')
            return False
        else:
            self.logger.success('Found the domain SID!')

        if args.output:
            outputfile(args, res)
            
        return res

    def as_rep(self, args):
        from impacket.ldap import ldap, ldapasn1
        crit = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % \
                       (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)
        att = ['sAMAccountName', 'pwdLastSet', 'lastLogon', 'MemberOf', 'objectSid']

        self.logger.info('Searching for AS-REP roastable users...')
        try:
            ldapConnection = ldap.LDAPConnection(f'ldap://{self.host}', self.base, self.host)
            ldapConnection.login(self.user, self.passwd)
            res  = ldapConnection.search(searchFilter=crit, attributes=None)
        except ldap.LDAPSearchError as err:
            if err.getErrorCode() == 1:
                self.logger.error('In order to perform this operation a successful bind must be completed on the connection.')
                self.logger.error('Enumerating AS-REP roastable users was unsuccessful!')
            else:
                self.logger.error(err)
            return False

        sAMAccountName = None
        memberOf = None

        asrep_users = []

        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            for att in item['attributes']:
                if str(att['type']) == 'sAMAccountName':
                    sAMAccountName = str(att['vals'][0])
                elif str(att['type']) == 'memberOf':
                    memberOf = str(att['vals'][0])
            asrep_users.append({'sAMAccountName':sAMAccountName, 'memberOf':memberOf})

        if args.output:
            outputfile(args, asrep_users)

        if sAMAccountName is not None and memberOf is not None:
            self.logger.success('Found a total of {} AS-REP roastable user(s)!'.format(len(asrep_users)))
            return asrep_users
        else:
            self.logger.error('Found a total of {} AS-REP roastable user(s)!'.format(len(asrep_users)))
            return False

    def groups(self, args):
        self.logger.info('Enumerating groups...')
    
        crit = "(objectClass=group)"
        att = ['name', 'distinguishedName']
        result = self._ldap_query(crit, att)

        if not result:
            self.logger.error('Enumerating groups was unsuccessful!')
            return False

        result = self._format_ldap_results(att, result)

        if len(result) > 0:
            self.logger.success('Found a total of {} groups'.format(len(result)))
        else:
            self.logger.error('Found a total of {} groups'.format(len(result)))

        if args.output:
            outputfile(args, result)

        return result

    def users(self, args):
        from impacket.ldap import ldap, ldapasn1

        self.logger.info('Enumerating domain users...')

        try:
            ldapConnection = ldap.LDAPConnection(f'ldap://{self.host}', self.base, self.host)
            ldapConnection.login(self.user, self.passwd)
        except ldap.LDAPSessionError as err:
            self.logger.error(err)
            return False

        crit = "(&(objectClass=user))"
        if args.filter is None and args.passwordspray is False:
            att = ['sAMAccountName', 'description', 'pwdLastSet', 'distinguishedName']
        elif args.passwordspray:
            att = ['sAMAccountName']
        else:
            att = args.filter.split(',')
            if args.only_desc:
                att.append('description')

        try:
            res = ldapConnection.search(searchFilter=crit, attributes=att)
        except ldap.LDAPSearchError as err:
            if err.getErrorCode() == 1:
                self.logger.error('In order to perform this operation a successful bind must be completed on the connection.')
            else:
                self.logger.error(err.errorString)
            self.logger.error('Enumerating users was unsuccessful!')
            return False

        result = []
        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            _temp = {}
            
            for c in att:
                for a in item['attributes']:
                    if c == str(a['type']):
                        _temp.update({c:str(a['vals'][0])})
                        break
                    else:
                        _temp.update({c:""})
            result.append(_temp)

        for u in result:
            try:
                u['pwdLastSet'] = ldap2datetime(float(u['pwdLastSet']))
                u['objectSid'] = convert_sid(u['objectSid'].encode('latin-1'))
            except KeyError:
                pass

        if args.passwordspray:
            self.logger.info('Generating user list for password spray...\n')
            result = [u['sAMAccountName'] for u in result]

        elif args.only_desc:
            _result = []

            for r in result:
                try:
                    if r['description'] != "":
                        _result.append(r)
                except KeyError:
                    pass
                else:
                    result = _result

        if args.output:
            if args.passwordspray:
                with open(args.output, 'w') as f:
                    for u in result:
                        f.write(u + '\n')
            else:
                outputfile(args, result)

        if len(result) > 0:
            self.logger.success('Found a total of {} users!'.format(len(result)))
            return result
        else:
            return False
    
    def _format_ldap_results(self, attributes, results):
        _data = []
        
        for entry in results:
            _temp = {}
            for att in attributes:
                try:
                    _temp.update({att:entry[att][0].decode('latin-1')})
                except KeyError:
                    _temp.update({att:""})
                    pass
            _data.append(_temp)
        return _data

    def _base_builder(self, domain):
        p = domain.split('.')
        base = ''
        for dc in p:
            base += f'dc={dc},'
        return base[:-1]

    def _ldap_query(self, criteria, attributes):
        try:
            result = self.ldap_conn.search_s(self.base, ldap.SCOPE_SUBTREE, criteria, attributes)
        except ldap.OPERATIONS_ERROR as err:
            if err.args[0]['msgtype'] == 101:
                self.logger.error('In order to perform this operation a successful bind must be completed on the connection.')
            return False
        except ldap.FILTER_ERROR:
            self.logger.error('Bad LDAP search filter.')
            return False
        else:
            results = [entry for dn, entry in result if isinstance(entry, dict)]
            return results

    def _setup_ldap_connection(self):
        try:
            conn = ldap.initialize(f"ldap://{self.host}")
            conn.protocol_version = ldap.VERSION3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.set_option(ldap.OPT_TIMEOUT, 5)
            conn.simple_bind_s(f'{self.user}@{self.domain}', self.passwd)
        except ldap.INVALID_CREDENTIALS:
            self.logger.error('LDAP credentials or domain incorrect.')
            sys.exit(-1)
        except ldap.SERVER_DOWN:
            self.logger.error('Could not connect to LDAP server! :(')
            sys.exit(-1)
        else:
            return conn

    def _determine_domain_name(self):
        self.logger.info('Domain parameter not set, trying to determine domain name automatically...')
        try:
            conn = ldap.initialize(f"ldap://{self.host}")
            domain_name = conn.get_naming_contexts()[0].decode().split(',')
            domain_name = [x[3:].strip() for x in domain_name]
            domain_name = ','.join(domain_name).replace(',','.')
        except Exception:
            return None
        else:
            self.logger.success(f'Using the following domain name: \033[1m{domain_name}\033[0m\n')
            return domain_name

    def __del__(self): # Destructor
        try:
            self.ldap_conn.unbind()
        except AttributeError:
            pass