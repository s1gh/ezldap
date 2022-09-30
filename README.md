# ezldap

```
python3 ezldap.py --help
          _     ____    _    ____  
  ___ ___| |   |  _ \  / \  |  _ \ 
 / _ \_  / |   | | | |/ _ \ | |_) |
|  __// /| |___| |_| / ___ \|  __/ 
 \___/___|_____|____/_/   \_\_|    
                                   
        "I always forget how to enumerate LDAP..."


usage: ezldap.py [-h] [--passpol] [--shares] [--users] [--groups] [--asrep] [--sid] [--check_laps] [--dump_laps] [--passwords] [--dump] [--query QUERY] [--filter FILTER] [--only_desc] [--passwordspray]
                 [--pretty] [--output OUTPUT] -i IP -u USERNAME -p PASSWORD -d DOMAIN

Required arguments:
  -i IP, --ip IP        IP/Hostname to target
  -u USERNAME, --username USERNAME
                        Username
  -p PASSWORD, --password PASSWORD
                        Password
  -d DOMAIN, --domain DOMAIN
                        Domain

Optional arguments:
  -h, --help            show this help message and exit
  --passpol             Enumerate password policy
  --shares              Enumerate SMB shares
  --users               Dump all users in domain
  --groups              Dump all groups in domain
  --asrep               Enumerate AS REP roastable users
  --sid                 Enumerate domain SID
  --check_laps          Check if LAPS is installed
  --dump_laps           Dump ms-Mcs-AdmPwd for all computer objects
  --passwords           Search for passwords stored in LDAP
  --dump                Dump all LDAP objects
  --query QUERY         Specify LDAP query manually
  --filter FILTER       Filter LDAP output (attributes) using a comma separated string
  --only_desc           Only show users with a description
  --passwordspray       Can be used with --users in order to get a formatted list of usernames
  --pretty              Pretty print the output
  --output OUTPUT       Write results to file
```
