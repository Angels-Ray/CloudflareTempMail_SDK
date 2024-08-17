import random
import string
from functools import wraps

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_random_name():
    """
    获取随机邮箱名称
    """
    # 生成5位英文字符
    letters1 = ''.join(random.choices(string.ascii_lowercase, k=5))
    # 生成1-3个数字
    numbers = ''.join(random.choices(string.digits, k=random.randint(1, 3)))
    # 生成1-3个英文字符
    letters2 = ''.join(random.choices(
        string.ascii_lowercase, k=random.randint(1, 3)))
    # 组合成最终名称
    return letters1 + numbers + letters2


class BaseApiClient:
    def __init__(self, admin_password=None, custom_password=None, worker_domain=None, jwt_token=None, ssl_verify=False,
                 proxy_url=None):
        self.admin_password = admin_password
        self.custom_password = custom_password
        self.worker_domain = worker_domain
        self.jwt_token = jwt_token
        self.ssl_verify = ssl_verify
        self.json_headers = {
            "Content-Type": "application/json"
        }

        if proxy_url:
            self.proxies = {
                "http": proxy_url,
                "https": proxy_url,
            }
        else:
            self.proxies = None

    def _make_request(self, method, url, headers=None, json=None):
        headers = headers or {}
        if self.admin_password:
            headers['x-admin-auth'] = self.admin_password
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        if self.custom_password:
            headers['x-custom-auth'] = self.custom_password

        if method == 'GET':
            response = requests.get(
                url, headers=headers, json=json, proxies=self.proxies, verify=self.ssl_verify)
        elif method == 'POST':
            response = requests.post(
                url, headers=headers, json=json, proxies=self.proxies, verify=self.ssl_verify)
        elif method == 'DELETE':
            response = requests.delete(
                url, headers=headers, json=json, proxies=self.proxies, verify=self.ssl_verify)
        else:
            raise ValueError("Unsupported HTTP method.")

        if response.status_code == 401:
            raise Exception(
                "Unauthorized request. Please check your credentials.")

        response.raise_for_status()
        return response.json()


def api_error_handler(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.HTTPError as http_err:
            raise Exception(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            raise Exception(f"Request error occurred: {req_err}")
        except Exception as e:
            raise Exception(f"An error occurred: {e}")

    return wrapper


class EmailManager(BaseApiClient):
    def __init__(self, admin_password=None, custom_password=None, worker_domain=None, jwt_token=None, ssl_verify=False,
                 proxy_url=None):
        """
        Cloudflare临时邮箱的简略sdk.
        @param admin_password: admin_password.
        @param custom_password: custom_password.
        @param worker_domain: Cloudflare worker domain or custom domain. e.g. xxx.workers.dev.
        @param jwt_token: The JWT token for the email. If JWT token is specified, fill it in.
        @param ssl_verify: SSL verification.
        @param proxy_url: http proxy.
        """
        super().__init__(admin_password, custom_password,
                         worker_domain, jwt_token, ssl_verify, proxy_url)
        self.addresses = {}
        self.name = None
        self.jwt_token = None
        self.domains = []

    @api_error_handler
    def create_email(self, name, domain, enable_prefix=True):
        """
        创建邮箱
        @param name: 邮箱名称
        @param domain: 可用的邮箱域名
        @param enable_prefix: 是否使用前缀
        @return: address, jwt_token
        """
        url = f"https://{self.worker_domain}/admin/new_address"
        payload = {
            "enablePrefix": enable_prefix,
            "name": name,
            "domain": domain,
        }

        data = self._make_request(
            'POST', url, headers=self.json_headers, json=payload)
        self.jwt_token = data.get('jwt', '')
        if self.jwt_token:
            return f"{name}@{domain}", self.jwt_token
        else:
            return '', ''

    def create_random_email(self, enable_prefix=True):
        """
        创建一个随机邮箱
        @param enable_prefix: 是否使用前缀
        @return: address, jwt_token
        """
        if not self.domains and not self.get_domains(set_to_self=True):
            return '', ''

        name = generate_random_name()
        domain = random.choice(self.domains)
        return self.create_email(name, domain, enable_prefix)

    @api_error_handler
    def delete_address(self, address_id):
        """
        删除邮箱
        @param address_id: 邮箱id
        @return: 是否删除成功
        """
        url = f"https://{self.worker_domain}/admin/delete_address/{address_id}"
        data = self._make_request('DELETE', url, headers=self.json_headers)

        return data.get('success', False)

    @api_error_handler
    def get_jwt_for_address(self, address_id):
        """
        获取邮箱的jwt
        @param address_id: 邮箱id
        @return: jwt
        """
        url = f"https://{self.worker_domain}/admin/show_password/{address_id}"
        data = self._make_request('GET', url, headers=self.json_headers)
        return data.get('jwt')

    @api_error_handler
    def query_addresses(self, limit=20, offset=0):
        url = f"https://{self.worker_domain}/admin/address?limit={limit}&offset={offset}"
        data = self._make_request('GET', url, headers=self.json_headers)
        self.addresses = {item['id']: item for item in data.get('results', [])}
        return self.addresses

    @api_error_handler
    def get_domains(self, set_to_self=True):
        """
        获取可用的邮箱域名
        @param set_to_self: 是否设置到self.domains
        @return: domains
        """
        url = f"https://{self.worker_domain}/open_api/settings"
        data = self._make_request('GET', url, headers=self.json_headers)
        domains = data.get('domains', [])
        if set_to_self:
            self.domains = domains
        return domains

    @api_error_handler
    def view_emails(self, limit=10, offset=0):
        """
        查看邮箱
        @param limit: 每页数量
        @param offset: 偏移量
        @return: emails
        """
        if not self.jwt_token:
            raise Exception(
                "JWT token is missing. Please create an email first or provide a JWT token.")

        url = f"https://{self.worker_domain}/api/mails?limit={limit}&offset={offset}"
        data = self._make_request('GET', url, headers=self.json_headers)
        emails = data.get('results', [])
        return emails

    def requset_send_mail_access(self):
        """
        请求发送邮件权限
        @return: 是否请求成功
        """
        url = f"https://{self.worker_domain}/api/requset_send_mail_access"
        data = self._make_request('POST', url, headers=self.json_headers)
        return data.get('success', '') == 'ok'

    @api_error_handler
    def send_email(self, from_name, to_name, to_mail, subject, content, is_html=False):
        """
        发送邮件
        @param from_name: 发件人名称
        @param to_name: 收件人名称
        @param to_mail: 收件人邮箱
        @param subject: 邮件主题
        @param content: 邮件内容
        @param is_html: 是否是html格式
        @return: 发送结果
        """
        if not self.jwt_token:
            raise Exception(
                "JWT token is missing. Please create an email first or provide a JWT token.")

        url = f"https://{self.worker_domain}/api/send_mail"
        send_body = {
            "from_name": from_name,
            "to_name": to_name,
            "to_mail": to_mail,
            "subject": subject,
            "is_html": is_html,
            "content": content,
        }

        data = self._make_request(
            'POST', url, headers=self.json_headers, json=send_body)
        return data

    @api_error_handler
    def delete_email(self, email_id):
        """
        删除邮件
        @param email_id: 邮件id
        @return: 是否删除成功
        """
        url = f"https://{self.worker_domain}/api/mails/{email_id}"
        data = self._make_request('DELETE', url, headers=self.json_headers)
        return data.get('success', False)

    def switch_address(self, address_id):
        """
        切换邮箱
        @param address_id: 邮箱id
        """
        address = self.addresses.get(address_id)
        if not address:
            raise Exception("Address not found.")

        self.name = address.get('name')
        self.jwt_token = self.get_jwt_for_address(address_id)


if __name__ == "__main__":
    # 使用示例
    email_manager = EmailManager(
        admin_password="xxx", custom_password="xxx", worker_domain="xxx.xxx.workers.dev",
        proxy_url="127.0.0.1:7890")

    try:
        # 创建邮箱
        email, jwt = email_manager.create_random_email()
        if not email:
            raise Exception("Failed to create email.")
        print(f"Created email: {email}")

        # 获取所有邮箱
        addresses = email_manager.query_addresses()
        print("Available addresses:", addresses)

        # 切换邮箱
        email_manager.switch_address(address_id=1)

        # 查看邮箱
        all_emails = email_manager.view_emails(limit=10, offset=0)
        print("Emails:", all_emails)

        # 发送邮件
        email_manager.requset_send_mail_access()
        send_status = email_manager.send_email(
            from_name="发件人名字",
            to_name="收件人名字",
            to_mail="recipient@example.com",
            subject="测试邮件",
            content="这是一个测试邮件内容"
        )
        print("Send status:", send_status)

    except Exception as err:
        print(f"An error occurred: {err}")
