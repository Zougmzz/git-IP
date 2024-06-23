import ctypes
import sys
import urllib.request
import re
import subprocess
import shutil
import os
import concurrent.futures
import time

def is_admin():
    """
    检查当前用户是否具有管理员权限
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_as_admin():
    """
    尝试以管理员权限重新运行当前脚本
    """
    # 获取当前脚本的完整路径
    script = os.path.abspath(sys.argv[0])
    
    # 构建命令行参数
    params = " ".join([script] + sys.argv[1:])
    
    try:
        # 调用ShellExecuteW以管理员权限重新运行脚本
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception as e:
        print(f"无法提升为管理员权限: {e}")
        sys.exit(1)

def download_file_from_github(url, local_filename):
    try:
        # 使用 urllib 下载文件，并禁用 SSL 验证
        context = urllib.request.ssl._create_unverified_context()
        with urllib.request.urlopen(url, context=context) as response, open(local_filename, 'wb') as out_file:
            data = response.read()
            out_file.write(data)
        print(f"文件下载成功并保存为 {local_filename}")
    except Exception as e:
        print(f"文件下载失败。错误信息: {e}")

def extract_domain_ip(local_filename):
    with open(local_filename, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    
    domain_ip_mapping = {}
    current_domain = ""
    
    # 正则表达式匹配域名和IP地址
    domain_pattern = re.compile(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    ip_pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}|(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+)')
    
    for line in lines:
        # 查找域名
        domain_match = domain_pattern.search(line)
        if domain_match:
            current_domain = domain_match.group(1)
            domain_ip_mapping[current_domain] = []
        
        # 查找IP地址
        ip_match = ip_pattern.search(line)
        if ip_match:
            ip_address = ip_match.group(1)
            if current_domain:
                domain_ip_mapping[current_domain].append(ip_address)
    
    return domain_ip_mapping

def ping_ip(ip):
    try:
        output = subprocess.check_output(["ping", "-n", "1", "-w", "1000", ip], universal_newlines=True)
        # 调整正则表达式，适应中文系统的 ping 输出格式
        time_ms = re.search(r'时间[=<](\d+\.?\d*)ms', output)
        if time_ms:
            ping_time = float(time_ms.group(1))
            if ping_time > 600:
                return float('inf')  # 如果延迟超过600ms，返回无穷大
            return ping_time
    except subprocess.CalledProcessError:
        return float('inf')  # 请求超时，返回无穷大

    return float('inf')  # 如果发生其他错误，也返回无穷大

def find_best_ip(domain_ip_mapping):
    best_ip_mapping = {}
    
    def process_domain(domain, ips):
        high_latency_ips = []
        for ip in ips:
            ping_time = ping_ip(ip)
            if ping_time < 600:
                high_latency_ips.append((ip, ping_time))
        if high_latency_ips:
            high_latency_ips.sort(key=lambda x: x[1])  # 按延迟时间排序
            return domain, high_latency_ips[0][0]  # 返回最低延迟的IP
        return domain, None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {executor.submit(process_domain, domain, ips): domain for domain, ips in domain_ip_mapping.items()}
        
        for future in concurrent.futures.as_completed(future_to_domain):
            domain, best_ip = future.result()
            if best_ip:
                best_ip_mapping[domain] = best_ip
            time.sleep(0.05)  # 线程间隔50ms
    
    return best_ip_mapping

def backup_hosts_file(hosts_path):
    try:
        backup_path = hosts_path + ".bak"
        shutil.copy(hosts_path, backup_path)
        print(f"已备份 hosts 文件到 {backup_path}")
    except Exception as e:
        print(f"备份 hosts 文件失败。错误信息: {e}")

def write_to_hosts(best_ip_mapping, hosts_path="C:\\Windows\\System32\\drivers\\etc\\hosts"):
    try:
        # 先备份 hosts 文件
        backup_hosts_file(hosts_path)
        
        # 读取原始 hosts 文件内容
        with open(hosts_path, 'r', encoding='utf-8') as hosts_file:
            lines = hosts_file.readlines()
        
        # 过滤掉需要更新的域名和已有的更新标记，并移除空行
        new_lines = []
        
        for line in lines:
            if any(domain in line for domain in best_ip_mapping.keys()):
                continue  # 跳过需要更新的行
            
            if line.strip().startswith("# Updated by script"):
                continue  # 跳过已有的更新标记行
            
            if line.strip() == "":
                continue  # 跳过空行
            
            new_lines.append(line)
        
        # 添加新的域名-IP映射，并在最后添加换行符
        new_lines.append("\n# Updated by script\n")
        for domain, best_ip in best_ip_mapping.items():
            new_lines.append(f"{best_ip} {domain}\n")
        
        # 写回 hosts 文件
        with open(hosts_path, 'w', encoding='utf-8') as hosts_file:
            hosts_file.writelines(new_lines)
        
        print("成功更新 hosts 文件")
    except Exception as e:
        print(f"更新 hosts 文件失败。错误信息: {e}")

def flush_dns_cache():
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=True)
        print("DNS缓存已刷新")
    except subprocess.CalledProcessError as e:
        print(f"刷新DNS缓存失败: {e}")

if __name__ == "__main__":
    if is_admin():
        # GitHub 上原始文件的 URL
        url = "https://raw.githubusercontent.com/Zougmzz/git-IP/main/IP.ini"
        local_filename = "IP.ini"

        # 从 GitHub 下载文件
        download_file_from_github(url, local_filename)

        # 提取域名和 IP 地址
        domain_ip_mapping = extract_domain_ip(local_filename)

        # 查找每个域名延迟最低的 IP 地址
        best_ip_mapping = find_best_ip(domain_ip_mapping)

        # 将最佳 IP 地址写入 hosts 文件
        write_to_hosts(best_ip_mapping)
        
        # 刷新 DNS 缓存
        flush_dns_cache()
    else:
        print("没有管理员权限，尝试提升权限...")
        run_as_admin()
