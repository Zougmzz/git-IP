import socket

def get_all_ip_addresses(domain):
    try:
        addresses = socket.getaddrinfo(domain, None)
        ip_addresses = list(set([addr[4][0] for addr in addresses]))
        return ip_addresses
    except socket.gaierror:
        return []

def read_domains_from_file(file_path):
    domains = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith('#'):
                domains.append(line)
    return domains

# 从域名.ini文件中读取域名列表
domains = read_domains_from_file('域名.ini')

# 获取每个域名的IP地址
ip_results = {}
for domain in domains:
    ips = get_all_ip_addresses(domain)
    ip_results[domain] = ips

# 将结果写入IP.ini文件
with open('IP.ini', 'w') as f:
    for domain, ips in ip_results.items():
        if ips:
            f.write(f'{domain} 的 IP 地址有：\n')
            for ip in ips:
                f.write(f'  {ip}\n')
        else:
            f.write(f'无法解析 {domain} 的 IP 地址\n')
