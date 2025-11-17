import shodan
import socket

API_KEY = "LZcHblTR6u4Rd2P70EbuSRD6VslppLNa"

def search_and_save(api_key, query="\"ntpd 4.2.6\"", filename="server.txt"):
    """
    修改后的函数，适用于 Shodan 免费帐户。
    移除了分页循环，因为免费帐户不支持分页。
    """
    api = shodan.Shodan(api_key)
    total_saved = 0

    print(f"正在使用免费帐户搜索: {query}")

    try:
        # 免费帐户不支持 'page' 参数，
        # 并且一次调用只会返回第一页（最多100个）结果
        results = api.search(query)

        # 打开文件以追加模式 (append mode)，并指定 utf-8 编码
        with open(filename, "a", encoding="utf-8") as file:
            for result in results['matches']:
                ip = result['ip_str']
                file.write(ip + "\n")
                total_saved += 1
        
        print(f"\n搜索完成。")
        # 显示 Shodan 报告的找到的总数
        print(f"Shodan 报告的总结果数: {results.get('total', 0)}")
        # 显示实际保存的数量
        print(f"已成功保存 {total_saved} 个IP地址到 {filename}")
        print("（注意：免费帐户限制为仅获取第一页结果）")

    except shodan.APIError as e:
        print(f"发生API错误: {e}")
    except Exception as e:
        print(f"发生意外错误: {e}")

def remove_duplicates():
    filename = "server.txt"
    with open(filename, "r") as file:
        unique_ips = list(set(line.strip() for line in file))

    with open(filename, "w") as file:
        for ip in unique_ips:
            file.write(ip + "\n")

    print(f"去重后{filename}有 {len(unique_ips)} 个IP地址")

def check_server(ntp_server_ip, port=123):
    # 构造一个NTP请求，其中包括monlist查询
    request = b'\x17\x00\x03\x2a' + b'\x00' * 4

    # 创建一个UDP套接字并连接到NTP服务器
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        s.sendto(request, (ntp_server_ip, port))
        try:
            response, _ = s.recvfrom(2048)
            # 检查响应是否包含至少一个monlist项
            if len(response) > 0:
                return True
        except socket.timeout:
            pass

    return False

def check_and_save_vulnerable_servers(filename="server.txt"):
    vulnerable_servers = []

    with open(filename, "r") as file:
        for line in file:
            ip = line.strip()
            try:
                if check_server(ip):
                    vulnerable_servers.append(ip)
                    print(f"发现漏洞的服务器: {ip}")
            except socket.error as e:
                pass

    with open(filename, "w") as file:
        for ip in vulnerable_servers:
            file.write(ip + "\n")

    print(f"保存了 {len(vulnerable_servers)} 个存在monlist漏洞的服务器到 {filename}")


if __name__ == "__main__":
    search_and_save(API_KEY)
    remove_duplicates()
    check_and_save_vulnerable_servers()
