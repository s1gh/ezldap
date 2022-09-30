import logging

class Logger():
    def __init__(self):
        self.log = logging.getLogger('ezldap')
        if not len(self.log.handlers):
            self.log.setLevel(logging.INFO)
            consoleHandler = logging.StreamHandler()
            consoleHandler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(message)s')
            consoleHandler.setFormatter(formatter)
            self.log.addHandler(consoleHandler)

    def info(self, msg):
        self.log.info(f'\033[1;36m\033[1m[+]\033[0m {msg}')

    def info_special(self, msg):
        self.log.info(f'\033[0;34m\033[1m[+] \033[1m{msg}\033[0m')

    def error(self, msg):
        self.log.info(f'\033[0;31m\033[1m[-]\033[0m {msg}')

    def success(self, msg):
        self.log.info(f'\033[1;32m\033[1m[!]\033[0m {msg}')