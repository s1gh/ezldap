from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from libs.logging import Logger
from helpers.helpers import outputfile


class SMBShares:
    def __init__(self, args):
        self.logger = Logger()
        self.args = args
        self.smb_connection = SMBConnection(args.ip, args.ip, None, 445, timeout=5)  # preferredDialect=SMB_DIALECT
        self.smb_connection.login(args.username, args.password, args.domain)
        self.shares = []
    
    def get_shares(self):
        self.logger.info('Enumerating shares...')
        
        try:
            for share in self.smb_connection.listShares():
                share_name = share['shi1_netname'][:-1]
                share_remark = share['shi1_remark'][:-1]
                share_dict = {'name': share_name, 'share_remark': share_remark, 'access': []}
            
                # Check if we have read access
                try:
                    self.smb_connection.listPath(share_name, '*')
                    share_dict['access'].append('R')
                except SessionError:
                    pass

                # Check if we have write access
                try:
                    self.smb_connection.createDirectory(share_name, 'ezLDAP')
                    self.smb_connection.deleteDirectory(share_name, 'ezLDAP')
                    share_dict['access'].append('W')
                except SessionError:
                    pass

                share_dict['access'] = ','.join(share_dict['access'])
                self.shares.append(share_dict)
            
            self.logger.success('Found a total of {} shares!'.format(len(self.shares)))
        except SessionError as err:
            if err.getErrorCode() == 3221225506:
                self.logger.error('STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.')
            else:
                self.logger.error(err)
            return False
        else:
            if self.args.output:
                self.outputfile(self.args, self.shares)
            return self.shares
