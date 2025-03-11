import socket
flagged_urls = []  

# Resolve a domain to IP
def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.error:
        return None

# Check if a flagged URL is accessed
def check_flagged_url():
    for url in flagged_urls:
        flagged_ip = resolve_domain_to_ip(url)
        print(url, flagged_ip)
    return None

check_flagged_url()
