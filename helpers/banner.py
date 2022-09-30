import pyfiglet

def show_banner():
    ascii_banner = pyfiglet.figlet_format("ezLDAP")
    slogan = "\t\"I always forget how to enumerate LDAP...\""
    print(f'\033[0;36m{ascii_banner}\033[0m\033[1;35m{slogan}\033[0m\n\n')