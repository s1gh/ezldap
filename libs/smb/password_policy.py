import sys
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5 import transport, samr 
from impacket.dcerpc.v5.samr import DCERPCSessionError
from impacket.dcerpc.v5.rpcrt import DCERPCException
from time import strftime,gmtime
from libs.logging import Logger

logger = Logger()

def d2b(a):
    tbin = []
    while a:
        tbin.append(a % 2)
        a //= 2

    t2bin = tbin[::-1]
    if len(t2bin) != 8:
        for x in range(6 - len(t2bin)):
            t2bin.insert(0, 0)
    return ''.join([str(g) for g in t2bin])


def convert(low, high, lockout=False):
    time = ""
    tmp = 0

    if low == 0 and hex(high) == "-0x80000000":
        return "Not Set"
    if low == 0 and high == 0:
        return "None"

    if not lockout:
        if (low != 0):
            high = abs(high+1)
        else:
            high = abs(high)
            low = abs(low)

        tmp = low + (high)*16**8  # convert to 64bit int
        tmp *= (1e-7)  # convert to seconds
    else:
        tmp = abs(high) * (1e-7)

    try:
        minutes = int(strftime("%M", gmtime(tmp)))
        hours = int(strftime("%H", gmtime(tmp)))
        days = int(strftime("%j", gmtime(tmp)))-1
    except ValueError as e:
        return "[-] Invalid TIME"

    if days > 1:
        time += "{0} days".format(days)
    elif days == 1:
        time += "{0} day".format(days)
    if hours > 1:
        time += "{0} hours".format(hours)
    elif hours == 1:
        time += "{0} hour".format(hours)
    if minutes > 1:
        time += "{0} minutes".format(minutes)
    elif minutes == 1:
        time += "{0} minute".format(minutes)
    return time

class PasswordPolicy:
    def __init__(self, args):
        self.host = args.ip
        self.username = args.username
        self.password = args.password
        self.domain = args.domain

    def dump_info(self):
        rpctransport = transport.SMBTransport(self.host, 445, r'\samr', self.username, self.password, self.domain, '', '', False)
        dce = DCERPC_v5(rpctransport)
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        pass_pol = {}

        # Setup stolen from CME
        try:
            logger.info('Enumerating password policy...')
            resp = samr.hSamrConnect2(dce)
        except samr.DCERPCSessionError as err:
            if err.get_error_code() == 3221225506:
                logger.error('STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.')
            else:
                logger.error(err)
            sys.exit(-1)

        if resp['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle=resp['ServerHandle'], enumerationContext=0, preferedMaximumLength=500)
        if resp2['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp3 = samr.hSamrLookupDomainInSamServer(dce, serverHandle=resp['ServerHandle'], name=resp2['Buffer']['Buffer'][0]['Name'])
        if resp3['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp4 = samr.hSamrOpenDomain(dce, serverHandle=resp['ServerHandle'], desiredAccess=samr.MAXIMUM_ALLOWED, domainId=resp3['DomainId'])
        if resp4['ErrorCode'] != 0:
            raise Exception('Connect error')

        self.__domains = resp2['Buffer']['Buffer']
        domainHandle = resp4['DomainHandle']
        # End of setup

        re = samr.hSamrQueryInformationDomain2(dce, domainHandle=domainHandle, domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)

        pass_pol['min_password_length'] = re['Buffer']['Password']['MinPasswordLength'] or "None"
        pass_pol['min_password_history'] = re['Buffer']['Password']['PasswordHistoryLength'] or "None"
        pass_pol['password_properties'] = d2b(re['Buffer']['Password']['PasswordProperties'])

        re = samr.hSamrQueryInformationDomain2(dce, domainHandle=domainHandle, domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)

        pass_pol['account_lockout_threshold'] = re['Buffer']['Lockout']['LockoutThreshold'] or "None"
        pass_pol['account_lockout_duration'] = convert(0, re['Buffer']['Lockout']['LockoutDuration'], lockout=True)

        dce.disconnect()

        if len(pass_pol) > 0:
            logger.success('Found password policy!\n')
            return pass_pol
        return False