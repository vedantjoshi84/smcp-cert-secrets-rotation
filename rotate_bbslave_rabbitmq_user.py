import logging
import argparse
import random
import string
import os
import requests
import base64

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s [%(levelname)s] %(message)s')
LOG = logging.getLogger(__name__)

def get_customer_info(fqdn):
    customer_uuid_encoded = kv_get(path='region_fqdns/{}/customer_uuid'.format(fqdn))
    customer_uuid = base64.b64decode(customer_uuid_encoded).decode('utf-8')
    print(customer_uuid)

    region_uuid_encoded = kv_get(path='region_fqdns/{}/region_uuid'.format(fqdn))
    region_uuid = base64.b64decode(region_uuid_encoded).decode('utf-8')
    print(region_uuid)

    customer_prefix = 'customers/{0}'.format(customer_uuid)
    region_prefix = '{0}/regions/{1}'.format(customer_prefix, region_uuid)

    return {
        'customer_prefix': customer_prefix,
        'region_prefix': region_prefix,
        'customer_uuid': customer_uuid,
        'region_uuid': region_uuid,
    }

def get_kv_tree_json(path):
    tree_details = {}
    for item in kv_get(path=path, recurse=True):
        tree_details[item['Key'].split('/')[-1]] = item['Value']
    return tree_details

def random_string():
    """
    16 random numbers and letters, always starts with a letter.
    """
    secret_len = 16
    secret_chars = string.ascii_letters + string.digits
    return ''.join([random.SystemRandom().choice(string.ascii_letters)] +
                   [random.SystemRandom().choice(secret_chars)
                    for _ in range(secret_len - 1)])

def decode_if_needed(value):
    if value.startswith('^') and value.endswith('$'):
        # Assuming it's not Base64 encoded if it starts and ends with '^' and '$'
        return value
    try:
        decoded_value = base64.b64decode(value).decode('utf-8')
        return decoded_value
    except Exception as e:
        LOG.warning('Failed to decode value: %s', e)
        return value

def rotate_bbslave_rabbitmq_user(fqdn):
    customer_info = get_customer_info(fqdn=fqdn)
    rabbit_users_base_path = '{}/rabbit_broker/users'.format(customer_info['region_prefix'])
    print("RABBIT USERS BASE PATH", rabbit_users_base_path)
    bbslave_user_path = '{}/bbslave'.format(rabbit_users_base_path)
    print("BBSLAVE USER PATH", bbslave_user_path)
    bbslave_user_json = get_kv_tree_json(path=bbslave_user_path)

    legacy_bbslave_user_path = '{}/bbslave_legacy'.format(rabbit_users_base_path)
    try:
        legacy_bbslave_password = kv_get(path='{}/password'.format(legacy_bbslave_user_path), raise_for_none=False)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            legacy_bbslave_password = None
        else:
            raise

    if legacy_bbslave_password:
        LOG.info('bbslave password was already rotated in consul.. Nothing to do')
        return

    LOG.info('rotating rabbitmq bbslave username & password in consul')
    for key, value in bbslave_user_json.items():
        decoded_value = decode_if_needed(value)
        path = '{}/{}'.format(legacy_bbslave_user_path, key)
        kv_put(path=path, value=decoded_value, update_only=False)
    bbslave_user_json['username'] = 'hostagent'
    bbslave_user_json['password'] = random_string()
    kv_put(path='{}/{}'.format(bbslave_user_path, 'username'), value=bbslave_user_json['username'], update_only=True)
    kv_put(path='{}/{}'.format(bbslave_user_path, 'password'), value=bbslave_user_json['password'], update_only=True)

    hostagent_user_path = '{}/hostagent'.format(rabbit_users_base_path)
    for key, value in bbslave_user_json.items():
        decoded_value = decode_if_needed(value)
        path = '{}/{}'.format(hostagent_user_path, key)
        kv_put(path=path, value=decoded_value, update_only=False)
    LOG.info('rotated rabbitmq bbslave username & password in consul')

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fqdn', required=True, dest='fqdn', default=None, help='DU fqdn')
    args = parser.parse_args()

    return args

def get_consul_headers():
    token = os.environ.get("CONSUL_HTTP_TOKEN", None)
    if not token:
        raise RuntimeError("must define CONSUL_HTTP_TOKEN env var")

    print("CONSUL_HTTP_TOKEN", token)
    return {'X-Consul-Token': token}

def get_consul_base_url():
    addr_env = os.environ.get("CONSUL_HTTP_ADDR", None)
    if not addr_env:
        raise RuntimeError("must define CONSUL_HTTP_ADDR env var")
    print("CONSUL_HTTP_ADDR", addr_env)
    return addr_env.rstrip('/')

def kv_get(path, recurse=False, raise_for_none=True):
    url = "{}/v1/kv/{}".format(get_consul_base_url(), path)
    params = {'recurse': 'true'} if recurse else {}
    response = requests.get(url, headers=get_consul_headers(), params=params)
    if response.status_code == 200:
        data = response.json()
        if not data:
            if raise_for_none:
                raise RuntimeError('nothing at %s' % path)
            else:
                return None
        if recurse:
            return data
        else:
            value = data[0]['Value']
            return value.decode('utf-8') if value else None
    else:
        response.raise_for_status()

def kv_put(path, value, update_only=True, raise_for_errors=True):
    if update_only:
        kv_get(path=path)
    url = "{}/v1/kv/{}".format(get_consul_base_url(), path)
    response = requests.put(url, headers=get_consul_headers(), data=value)
    if response.status_code != 200:
        if raise_for_errors:
            raise RuntimeError('update value failed for %s' % path)
    return response.status_code == 200

def main():
    args = parse_args()
    rotate_bbslave_rabbitmq_user(args.fqdn)

if __name__ == '__main__':
    main()

