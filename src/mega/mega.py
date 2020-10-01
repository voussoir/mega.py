import binascii
import hashlib
import json
import logging
import math
import os
import pathlib
import random
import re
import requests
import secrets
import shutil
import tempfile
import tenacity
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter

from . import crypto
from . import errors

logger = logging.getLogger(__name__)

NODE_TYPE_FILE = 0
NODE_TYPE_DIR = 1
NODE_TYPE_ROOT = 2
NODE_TYPE_INBOX = 3
NODE_TYPE_TRASH = 4

class Mega:
    def __init__(self, options=None):
        self.schema = 'https'
        self.domain = 'mega.co.nz'
        self.timeout = 160  # max secs to wait for resp from api requests
        self.sid = None
        self.sequence_num = random.randint(0, 0xFFFFFFFF)
        self.request_id = crypto.make_id(10)
        self._trash_folder_node_id = None
        self.shared_keys = {}

        if options is None:
            options = {}
        self.options = options

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(errors.EAGAIN),
        wait=tenacity.wait_exponential(multiplier=2, min=2, max=60)
    )
    def _api_request(self, data, params={}):
        req_params = {'id': self.sequence_num}
        self.sequence_num += 1

        if self.sid:
            req_params.update({'sid': self.sid})

        req_params.update(params)

        # ensure input data is a list
        if not isinstance(data, list):
            data = [data]

        url = f'{self.schema}://g.api.{self.domain}/cs'
        req = requests.post(
            url,
            params=req_params,
            data=json.dumps(data),
            timeout=self.timeout,
        )
        json_resp = json.loads(req.text)
        if isinstance(json_resp, list) and isinstance(json_resp[0], int):
            json_resp = json_resp[0]
        if isinstance(json_resp, int):
            # If this raises EAGAIN it'll be caught by tenacity retry.
            raise errors.error_for_code(json_resp)
        if len(json_resp) == 1:
            return json_resp[0]
        else:
            return json_resp

    def _api_account_version_and_salt(self, email):
        """
        The `us0` request returns a dictionary like
        {'v': 1} if the account is a v1 account, or
        {'v': 2, 's': '*salt*'} if the account is v2 or higher.

        This function will return a tuple (version, salt) where salt is None
        if the version is 1.
        """
        resp = self._api_request({'a': 'us0', 'user': email})
        account_version = resp['v']
        user_salt = resp.get('s', None)
        return (account_version, user_salt)

    def _api_start_session(self, user, user_hash=None):
        """
        The `us` request returns a dictionary like
        {
            'tsid': 'session' (if temporary session),
            'csid': 'session' (if login session),
            'privk': 'private key' (which must be decoded),
            'k': 'master key' (which must be decoded),
            'u': 'user id',
            'ach': 1 (I don't know, it's always 1 for me)
        }
        """
        request = {'a': 'us', 'user': user}
        if user_hash is not None:
            request['uh'] = user_hash
        resp = self._api_request(request)
        return resp

    def login(self, email=None, password=None):
        if email:
            self._login_user(email, password)
        else:
            self.login_anonymous()
        self._trash_folder_node_id = self.get_node_by_type(NODE_TYPE_TRASH)[0]
        logger.info('Login complete')
        return self

    def _login_user(self, email, password):
        logger.info('Logging in user...')
        email = email.lower()
        (account_version, user_salt) = self._api_account_version_and_salt(email)
        logger.debug('User account is version %d.', account_version)
        if account_version >= 2:
            user_salt = crypto.base64_to_a32(user_salt)
            # Parameters specified by MEGA's webclient security.js, search for
            # "numOfIterations" and deriveKeyWithWebCrypto to cross-reference.
            pbkdf2_key = hashlib.pbkdf2_hmac(
                hash_name='sha512',
                password=password.encode(),
                salt=crypto.a32_to_str(user_salt),
                iterations=100000,
                dklen=32
            )
            password_aes = crypto.str_to_a32(pbkdf2_key[:16])
            user_hash = crypto.base64_url_encode(pbkdf2_key[-16:])
        else:
            password_a32 = crypto.str_to_a32(password)
            password_aes = crypto.prepare_key(password_a32)
            user_hash = crypto.stringhash(email, password_aes)

        resp = self._api_start_session(email, user_hash)
        if isinstance(resp, int):
            raise errors.RequestError(resp)
        self._login_process(resp, password_aes)

    def login_anonymous(self):
        logger.info('Logging in anonymous temporary user...')
        master_key = [random.randint(0, 0xFFFFFFFF)] * 4
        password_key = [random.randint(0, 0xFFFFFFFF)] * 4
        session_self_challenge = [random.randint(0, 0xFFFFFFFF)] * 4

        k = crypto.a32_to_base64(crypto.encrypt_key(master_key, password_key))
        ts = crypto.a32_to_str(session_self_challenge)
        ts += crypto.a32_to_str(crypto.encrypt_key(session_self_challenge, master_key))
        ts = crypto.base64_url_encode(ts)
        user = self._api_request({'a': 'up', 'k': k, 'ts': ts})

        resp = self._api_start_session(user)
        if isinstance(resp, int):
            raise errors.RequestError(resp)
        self._login_process(resp, password_key)

    def _login_process(self, resp, password):
        encrypted_master_key = crypto.base64_to_a32(resp['k'])
        self.master_key = crypto.decrypt_key(encrypted_master_key, password)
        # tsid is for temporary sessions
        if 'tsid' in resp:
            tsid = crypto.base64_url_decode(resp['tsid'])
            key_encrypted = crypto.a32_to_str(
                crypto.encrypt_key(crypto.str_to_a32(tsid[:16]), self.master_key)
            )
            if key_encrypted == tsid[-16:]:
                self.sid = resp['tsid']
        # csid is for user logins
        elif 'csid' in resp:
            encrypted_rsa_private_key = crypto.base64_to_a32(resp['privk'])
            rsa_private_key = crypto.decrypt_key(
                encrypted_rsa_private_key, self.master_key
            )

            private_key = crypto.a32_to_str(rsa_private_key)
            # The private_key contains 4 MPI integers concatenated together.
            rsa_private_key = [0, 0, 0, 0]
            for i in range(4):
                # An MPI integer has a 2-byte header which describes the number
                # of bits in the integer.
                bitlength = (private_key[0] * 256) + private_key[1]
                bytelength = math.ceil(bitlength / 8)
                # Add 2 bytes to accommodate the MPI header
                bytelength += 2
                rsa_private_key[i] = crypto.mpi_to_int(private_key[:bytelength])
                private_key = private_key[bytelength:]

            first_factor_p = rsa_private_key[0]
            second_factor_q = rsa_private_key[1]
            private_exponent_d = rsa_private_key[2]
            # In MEGA's webclient javascript, they assign [3] to a variable
            # called u, but I do not see how it corresponds to pycryptodome's
            # RSA.construct and it does not seem to be necessary.
            rsa_modulus_n = first_factor_p * second_factor_q
            phi = (first_factor_p - 1) * (second_factor_q - 1)
            public_exponent_e = crypto.modular_inverse(private_exponent_d, phi)

            rsa_components = (
                rsa_modulus_n,
                public_exponent_e,
                private_exponent_d,
                first_factor_p,
                second_factor_q,
            )
            rsa_decrypter = RSA.construct(rsa_components)

            encrypted_sid = crypto.mpi_to_int(crypto.base64_url_decode(resp['csid']))

            sid = '%x' % rsa_decrypter._decrypt(encrypted_sid)
            sid = binascii.unhexlify('0' + sid if len(sid) % 2 else sid)
            self.sid = crypto.base64_url_encode(sid[:43])

    def _parse_url(self, url):
        """
        Given a url like 'https://mega.nz/#!fileid!filekey', return a tuple
        (fileid, filekey).
        """
        # File urls are '#!', Folder urls are '#F!'
        if '/file/' in url:
            # V2 URL structure
            url = url.replace(' ', '')
            file_id = re.findall(r'\W\w\w\w\w\w\w\w\w\W', url)[0][1:-1]
            id_index = re.search(file_id, url).end()
            key = url[id_index + 1:]
            return f'{file_id}!{key}'
        elif '!' in url:
            match = re.findall(r'/#F?!(.*)!(.*)', url)
            if not match:
                raise errors.ValidationError('Invalid public url. Should have /#!id!key')
            (public_handle, decryption_key) = match[0]
            return (public_handle, decryption_key)

    def _process_file(self, file):
        if file['t'] in [NODE_TYPE_FILE, NODE_TYPE_DIR]:
            keys = dict(
                keypart.split(':', 1) for keypart in file['k'].split('/')
                if ':' in keypart)
            uid = file['u']
            key = None
            # my objects
            if uid in keys:
                key = crypto.decrypt_key(crypto.base64_to_a32(keys[uid]), self.master_key)
            # shared folders
            elif 'su' in file and 'sk' in file and ':' in file['k']:
                shared_key = crypto.decrypt_key(
                    crypto.base64_to_a32(file['sk']), self.master_key
                )
                key = crypto.decrypt_key(crypto.base64_to_a32(keys[file['h']]), shared_key)
                if file['su'] not in self.shared_keys:
                    self.shared_keys[file['su']] = {}
                self.shared_keys[file['su']][file['h']] = shared_key
            # shared files
            elif file['u'] and file['u'] in self.shared_keys:
                for hkey in self.shared_keys[file['u']]:
                    shared_key = self.shared_keys[file['u']][hkey]
                    if hkey in keys:
                        key = keys[hkey]
                        key = crypto.decrypt_key(crypto.base64_to_a32(key), shared_key)
                        break
            if file['h'] and file['h'] in self.shared_keys.get('EXP', ()):
                shared_key = self.shared_keys['EXP'][file['h']]
                encrypted_key = crypto.str_to_a32(
                    crypto.base64_url_decode(file['k'].split(':')[-1])
                )
                key = crypto.decrypt_key(encrypted_key, shared_key)
                file['shared_folder_key'] = shared_key
            if key is not None:
                if file['t'] == NODE_TYPE_FILE:
                    k = crypto.interleave_xor_8(key)
                    file['iv'] = key[4:6] + (0, 0)
                    file['meta_mac'] = key[6:8]
                else:
                    k = key
                file['key'] = key
                file['k'] = k
                attributes = crypto.base64_url_decode(file['a'])
                attributes = crypto.decrypt_attr(attributes, k)
                file['a'] = attributes
            # other => wrong object
            elif file['k'] == '':
                file['a'] = False
        elif file['t'] == NODE_TYPE_ROOT:
            self.root_id = file['h']
            file['a'] = {'n': 'Cloud Drive'}
        elif file['t'] == NODE_TYPE_INBOX:
            self.inbox_id = file['h']
            file['a'] = {'n': 'Inbox'}
        elif file['t'] == NODE_TYPE_TRASH:
            self.trashbin_id = file['h']
            file['a'] = {'n': 'Rubbish Bin'}
        return file

    def _init_shared_keys(self, files):
        """
        Init shared key not associated with a user.
        Seems to happen when a folder is shared,
        some files are exchanged and then the
        folder is un-shared.
        Keys are stored in files['s'] and files['ok']
        """
        ok_dict = {}

        for ok_item in files.get('ok', []):
            shared_key = crypto.decrypt_key(
                crypto.base64_to_a32(ok_item['k']), self.master_key
            )
            ok_dict[ok_item['h']] = shared_key
        for s_item in files.get('s', []):
            if s_item['u'] not in self.shared_keys:
                self.shared_keys[s_item['u']] = {}
            if s_item['h'] in ok_dict:
                self.shared_keys[s_item['u']][s_item['h']] = ok_dict[s_item['h']]

    def find_path_descriptor(self, path, files=()):
        """
        Find descriptor of folder inside a path. i.e.: folder1/folder2/folder3
        Params:
            path: string like 'folder1/folder2/folder3'
        Return:
            Descriptor (str) of folder3 if exists, None otherwise
        """
        paths = path.split('/')

        files = files or self.get_files()
        parent_desc = self.root_id
        found = False
        for foldername in paths:
            if foldername != '':
                for file in files.items():
                    if (file[1]['a'] and file[1]['t']
                            and file[1]['a']['n'] == foldername):
                        if parent_desc == file[1]['p']:
                            parent_desc = file[0]
                            found = True
                if found:
                    found = False
                else:
                    return None
        return parent_desc

    def find(self, filename=None, handle=None, exclude_deleted=False):
        """
        Return file object from given filename
        """
        files = self.get_files()
        if handle:
            return files[handle]
        path = pathlib.Path(filename)
        filename = path.name
        parent_dir_name = path.parent.name
        for file in list(files.items()):
            parent_node_id = None
            try:
                if parent_dir_name:
                    parent_node_id = self.find_path_descriptor(parent_dir_name,
                                                               files=files)
                    if (filename and parent_node_id and file[1]['a']
                            and file[1]['a']['n'] == filename
                            and parent_node_id == file[1]['p']):
                        if (exclude_deleted and self._trash_folder_node_id
                                == file[1]['p']):
                            continue
                        return file
                elif (filename and file[1]['a']
                      and file[1]['a']['n'] == filename):
                    if (exclude_deleted
                            and self._trash_folder_node_id == file[1]['p']):
                        continue
                    return file
            except TypeError:
                continue

    def get_files(self, public_folder_handle=None):
        logger.info('Getting all files...')

        params = {}
        if public_folder_handle is not None:
            params['n'] = public_folder_handle

        files = self._api_request({'a': 'f', 'c': 1, 'r': 1}, params=params)

        files_dict = {}
        self._init_shared_keys(files)
        for file in files['f']:
            processed_file = self._process_file(file)
            # ensure each file has a name before returning
            if processed_file['a']:
                files_dict[file['h']] = processed_file
        return files_dict

    def get_upload_link(self, file):
        """
        Get a file's public link including decryption key
        Requires upload() response as input
        """
        if 'f' in file:
            file = file['f'][0]
            public_handle = self._api_request({'a': 'l', 'n': file['h']})
            file_key = file['k'][file['k'].index(':') + 1:]
            decrypted_key = crypto.a32_to_base64(
                crypto.decrypt_key(crypto.base64_to_a32(file_key), self.master_key)
            )
            return (
                f'{self.schema}://{self.domain}'
                f'/#!{public_handle}!{decrypted_key}'
            )
        else:
            raise ValueError('''Upload() response required as input,
                            use get_link() for regular file input''')

    def get_link(self, file):
        """
        Get a file public link from given file object
        """
        file = file[1]
        if 'h' in file and 'k' in file:
            public_handle = self._api_request({'a': 'l', 'n': file['h']})
            if public_handle == -11:
                raise errors.RequestError(
                    "Can't get a public link from that file "
                    "(is this a shared file?)"
                )
            decrypted_key = crypto.a32_to_base64(file['key'])
            return (
                f'{self.schema}://{self.domain}'
                f'/#!{public_handle}!{decrypted_key}'
            )
        else:
            raise errors.ValidationError('File id and key must be present')

    def _node_data(self, node):
        try:
            return node[1]
        except (IndexError, KeyError):
            return node

    def get_folder_link(self, file):
        try:
            file = file[1]
        except (IndexError, KeyError):
            pass
        if 'h' in file and 'k' in file:
            public_handle = self._api_request({'a': 'l', 'n': file['h']})
            if public_handle == -11:
                raise errors.RequestError(
                    "Can't get a public link from that file "
                    "(is this a shared file?)"
                )
            decrypted_key = crypto.a32_to_base64(file['shared_folder_key'])
            return (
                f'{self.schema}://{self.domain}'
                f'/#F!{public_handle}!{decrypted_key}'
            )
        else:
            raise errors.ValidationError('File id and key must be present')

    def get_user(self):
        user_data = self._api_request({'a': 'ug'})
        return user_data

    def get_node_by_type(self, type):
        """
        Get a node by it's numeric type id, e.g:
        2: special: root cloud drive
        3: special: inbox
        4: special: trash bin
        """
        # Should we also check for NODE_TYPE_FILE, NODE_TYPE_DIR here?
        nodes = self.get_files()
        for node in list(nodes.items()):
            if node[1]['t'] == type:
                return node

    def get_files_in_node(self, target):
        """
        Get all files in a given target.
        Params:
            target: a node's id string, or one of the special nodes
                e.g. NODE_TYPE_TRASH.
        """
        if type(target) == int:
            if target in [NODE_TYPE_FILE, NODE_TYPE_DIR]:
                raise TypeError('Can\'t use file or dir node type.')
            node_id = self.get_node_by_type(target)[0]
        else:
            node_id = target

        files = self._api_request({'a': 'f', 'c': 1})
        # MERGE COMMON CODE WITH GET_FILES
        files_dict = {}
        self._init_shared_keys(files)
        for file in files['f']:
            processed_file = self._process_file(file, self.shared_keys)
            if processed_file['a'] and processed_file['p'] == node_id:
                files_dict[file['h']] = processed_file
        return files_dict

    def get_id_from_public_handle(self, public_handle):
        node_data = self._api_request({'a': 'f', 'f': 1, 'p': public_handle})
        node_id = self.get_id_from_obj(node_data)
        return node_id

    def get_id_from_obj(self, node_data):
        """
        Get node id from a file object
        """
        node_id = None

        for i in node_data['f']:
            if i['h'] != '':
                node_id = i['h']
        return node_id

    def get_quota(self):
        """
        Get current remaining disk quota in MegaBytes
        """
        request = {
            'a': 'uq',
            'xfer': 1,
            'strg': 1,
            'v': 1
        }
        json_resp = self._api_request(request)
        # convert bytes to megabyes
        return json_resp['mstrg'] / 1048576

    def get_storage_space(self, giga=False, mega=False, kilo=False):
        """
        Get the current storage space.
        Return a dict containing at least:
          'used' : the used space on the account
          'total' : the maximum space allowed with current plan
        All storage space are in bytes unless asked differently.
        """
        if sum(bool(x) for x in (kilo, mega, giga)) > 1:
            raise ValueError("Only one unit prefix can be specified")
        unit_coef = 1
        if kilo:
            unit_coef = 1024
        if mega:
            unit_coef = 1048576
        if giga:
            unit_coef = 1073741824
        json_resp = self._api_request({'a': 'uq', 'xfer': 1, 'strg': 1})
        return {
            'used': json_resp['cstrg'] / unit_coef,
            'total': json_resp['mstrg'] / unit_coef,
        }

    def get_balance(self):
        """
        Get account monetary balance, Pro accounts only
        """
        user_data = self._api_request({"a": "uq", "pro": 1})
        if 'balance' in user_data:
            return user_data['balance']

    def delete(self, public_handle):
        """
        Delete a file by its public handle
        """
        return self.move(public_handle, NODE_TYPE_TRASH)

    def delete_url(self, url):
        """
        Delete a file by its url
        """
        (public_handle, decryption_key) = self._parse_url(url)
        file_id = self.get_id_from_public_handle(public_handle)
        return self.move(file_id, NODE_TYPE_TRASH)

    def destroy(self, file_id):
        """
        Destroy a file by its private id
        """
        request = {
            'a': 'd',
            'n': file_id,
            'i': self.request_id
        }
        return self._api_request(request)

    def destroy_url(self, url):
        """
        Destroy a file by its url
        """
        (public_handle, decryption_key) = self._parse_url(url)
        file_id = self.get_id_from_public_handle(public_handle)
        return self.destroy(file_id)

    def empty_trash(self):
        # get list of files in rubbish out
        files = self.get_files_in_node(NODE_TYPE_TRASH)

        # make a list of json
        if files != {}:
            post_list = []
            for file in files:
                post_list.append({"a": "d", "n": file, "i": self.request_id})
            return self._api_request(post_list)

    def download(self, file, dest_path=None, dest_filename=None):
        """
        Download a file by it's file object
        """
        return self._download_file(file_handle=None,
                                   file_key=None,
                                   file=file[1],
                                   dest_path=dest_path,
                                   dest_filename=dest_filename,
                                   is_public=False)

    def _export_file(self, node):
        node_data = self._node_data(node)
        self._api_request([{
            'a': 'l',
            'n': node_data['h'],
            'i': self.request_id
        }])
        return self.get_link(node)

    def export(self, path=None, node_id=None):
        if node_id:
            nodes = self.get_files()
            node = nodes[node_id]
        else:
            node = self.find(path)

        node_data = self._node_data(node)
        is_file_node = node_data['t'] == NODE_TYPE_FILE
        if is_file_node:
            return self._export_file(node)
        if node:
            try:
                # If already exported
                return self.get_folder_link(node)
            except (errors.RequestError, KeyError):
                pass

        master_key_cipher = AES.new(crypto.a32_to_str(self.master_key), AES.MODE_ECB)
        ha = crypto.base64_url_encode(
            master_key_cipher.encrypt(node_data['h'].encode("utf8") + node_data['h'].encode("utf8"))
        )

        share_key = secrets.token_bytes(16)
        ok = crypto.base64_url_encode(master_key_cipher.encrypt(share_key))

        share_key_cipher = AES.new(share_key, AES.MODE_ECB)
        node_key = node_data['k']
        encrypted_node_key = crypto.base64_url_encode(
            share_key_cipher.encrypt(crypto.a32_to_str(node_key))
        )

        node_id = node_data['h']
        request_body = [{
            'a':
            's2',
            'n':
            node_id,
            's': [{
                'u': 'EXP',
                'r': 0
            }],
            'i':
            self.request_id,
            'ok':
            ok,
            'ha':
            ha,
            'cr': [[node_id], [node_id], [0, 0, encrypted_node_key]]
        }]
        self._api_request(request_body)
        nodes = self.get_files()
        return self.get_folder_link(nodes[node_id])

    def download_url(self, url, dest_path=None, dest_filename=None):
        """
        Download a file by it's public url
        """
        (public_handle, decryption_key) = self._parse_url(url)
        return self._download_file(
            file_handle=public_handle,
            file_key=decryption_key,
            dest_path=dest_path,
            dest_filename=dest_filename,
            is_public=True,
        )

    def _download_file(self,
                       file_handle,
                       file_key,
                       dest_path=None,
                       dest_filename=None,
                       is_public=False,
                       file=None):
        if file is None:
            if is_public:
                file_key = crypto.base64_to_a32(file_key)
                request = {
                    'a': 'g',
                    'g': 1,
                    'p': file_handle
                }
            else:
                request = {
                    'a': 'g',
                    'g': 1,
                    'n': file_handle
                }
            file_data = self._api_request(request)
            k = crypto.interleave_xor_8(file_key)
            iv = file_key[4:6] + (0, 0)
            meta_mac = file_key[6:8]
        else:
            file_data = self._api_request({'a': 'g', 'g': 1, 'n': file['h']})
            k = file['k']
            iv = file['iv']
            meta_mac = file['meta_mac']

        # Seems to happens sometime... When this occurs, files are
        # inaccessible also in the official also in the official web app.
        # Strangely, files can come back later.
        if 'g' not in file_data:
            raise errors.RequestError('File not accessible anymore')
        file_url = file_data['g']
        file_size = file_data['s']
        attribs = crypto.base64_url_decode(file_data['at'])
        attribs = crypto.decrypt_attr(attribs, k)

        if dest_filename is not None:
            file_name = dest_filename
        else:
            file_name = attribs['n']

        input_file = requests.get(file_url, stream=True).raw

        if dest_path is None:
            dest_path = ''
        else:
            dest_path += '/'

        temp_output_file = tempfile.NamedTemporaryFile(
            mode='w+b', prefix='megapy_', delete=False
        )
        with temp_output_file:
            k_str = crypto.a32_to_str(k)
            counter = Counter.new(
                128, initial_value=((iv[0] << 32) + iv[1]) << 64
            )
            aes = AES.new(k_str, AES.MODE_CTR, counter=counter)
            mac_str = '\0' * 16
            mac_encryptor = AES.new(k_str, AES.MODE_CBC, mac_str.encode("utf8"))
            iv_str = crypto.a32_to_str([iv[0], iv[1], iv[0], iv[1]])

            for chunk_start, chunk_size in crypto.get_chunks(file_size):
                chunk = input_file.read(chunk_size)
                chunk = aes.decrypt(chunk)
                temp_output_file.write(chunk)

                encryptor = AES.new(k_str, AES.MODE_CBC, iv_str)
                for i in range(0, len(chunk) - 16, 16):
                    block = chunk[i:i + 16]
                    encryptor.encrypt(block)

                # fix for files under 16 bytes failing
                if file_size > 16:
                    i += 16
                else:
                    i = 0

                block = chunk[i:i + 16]
                if len(block) % 16:
                    block += b'\0' * (16 - (len(block) % 16))
                mac_str = mac_encryptor.encrypt(encryptor.encrypt(block))

                file_info = os.stat(temp_output_file.name)
                logger.info(
                    '%s of %s downloaded', file_info.st_size, file_size
                )
            file_mac = crypto.str_to_a32(mac_str)
            # check mac integrity
            if (file_mac[0] ^ file_mac[1],
                    file_mac[2] ^ file_mac[3]) != meta_mac:
                raise ValueError('Mismatched mac')
            output_path = pathlib.Path(dest_path + file_name)
            shutil.move(temp_output_file.name, output_path)
            return output_path

    def upload(self, filename, dest=None, dest_filename=None):
        # determine storage node
        if dest is None:
            # if none set, upload to cloud drive node
            if not hasattr(self, 'root_id'):
                self.get_files()
            dest = self.root_id

        # request upload url, call 'u' method
        with open(filename, 'rb') as input_file:
            file_size = os.path.getsize(filename)
            ul_url = self._api_request({'a': 'u', 's': file_size})['p']

            # generate random aes key (128) for file
            ul_key = [random.randint(0, 0xFFFFFFFF) for _ in range(6)]
            k_str = crypto.a32_to_str(ul_key[:4])
            count = Counter.new(
                128, initial_value=((ul_key[4] << 32) + ul_key[5]) << 64)
            aes = AES.new(k_str, AES.MODE_CTR, counter=count)

            upload_progress = 0
            completion_file_handle = None

            mac_str = '\0' * 16
            mac_encryptor = AES.new(k_str, AES.MODE_CBC, mac_str.encode("utf8"))
            iv_str = crypto.a32_to_str([ul_key[4], ul_key[5], ul_key[4], ul_key[5]])
            if file_size > 0:
                for chunk_start, chunk_size in crypto.get_chunks(file_size):
                    chunk = input_file.read(chunk_size)
                    upload_progress += len(chunk)

                    encryptor = AES.new(k_str, AES.MODE_CBC, iv_str)
                    for i in range(0, len(chunk) - 16, 16):
                        block = chunk[i:i + 16]
                        encryptor.encrypt(block)

                    # fix for files under 16 bytes failing
                    if file_size > 16:
                        i += 16
                    else:
                        i = 0

                    block = chunk[i:i + 16]
                    if len(block) % 16:
                        block += crypto.makebyte('\0' * (16 - len(block) % 16))
                    mac_str = mac_encryptor.encrypt(encryptor.encrypt(block))

                    # encrypt file and upload
                    chunk = aes.encrypt(chunk)
                    output_file = requests.post(ul_url + "/" +
                                                str(chunk_start),
                                                data=chunk,
                                                timeout=self.timeout)
                    completion_file_handle = output_file.text
                    logger.info('%s of %s uploaded', upload_progress,
                                file_size)
            else:
                output_file = requests.post(ul_url + "/0",
                                            data='',
                                            timeout=self.timeout)
                completion_file_handle = output_file.text

            logger.info('Chunks uploaded')
            logger.info('Setting attributes to complete upload')
            logger.info('Computing attributes')
            file_mac = crypto.str_to_a32(mac_str)

            # determine meta mac
            meta_mac = (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3])

            dest_filename = dest_filename or os.path.basename(filename)
            attribs = {'n': dest_filename}

            encrypt_attribs = crypto.base64_url_encode(
                crypto.encrypt_attr(attribs, ul_key[:4])
            )
            key = [
                ul_key[0] ^ ul_key[4], ul_key[1] ^ ul_key[5],
                ul_key[2] ^ meta_mac[0], ul_key[3] ^ meta_mac[1], ul_key[4],
                ul_key[5], meta_mac[0], meta_mac[1]
            ]
            encrypted_key = crypto.a32_to_base64(crypto.encrypt_key(key, self.master_key))
            logger.info('Sending request to update attributes')
            # update attributes
            request = {
                'a': 'p',
                't': dest,
                'i': self.request_id,
                'n': [
                    {
                        'h': completion_file_handle,
                        't': NODE_TYPE_FILE,
                        'a': encrypt_attribs,
                        'k': encrypted_key
                    }
                ]
            }
            data = self._api_request(request)
            logger.info('Upload complete')
            return data

    def _mkdir(self, name, parent_node_id):
        # generate random aes key (128) for folder
        ul_key = [random.randint(0, 0xFFFFFFFF) for _ in range(6)]

        # encrypt attribs
        attribs = {'n': name}
        encrypt_attribs = crypto.base64_url_encode(crypto.encrypt_attr(attribs, ul_key[:4]))
        encrypted_key = crypto.a32_to_base64(crypto.encrypt_key(ul_key[:4], self.master_key))

        # update attributes
        request = {
            'a': 'p',
            't': parent_node_id,
            'n': [
                {
                    'h': 'xxxxxxxx',
                    't': NODE_TYPE_DIR,
                    'a': encrypt_attribs,
                    'k': encrypted_key
                }
            ],
            'i': self.request_id
        }
        data = self._api_request(request)
        return data

    def _root_node_id(self):
        if not hasattr(self, 'root_id'):
            self.get_files()
        return self.root_id

    def create_folder(self, name, dest=None):
        dirs = tuple(dir_name for dir_name in str(name).split('/') if dir_name)
        folder_node_ids = {}
        for idx, directory_name in enumerate(dirs):
            existing_node_id = self.find_path_descriptor(directory_name)
            if existing_node_id:
                folder_node_ids[idx] = existing_node_id
                continue
            if idx == 0:
                if dest is None:
                    parent_node_id = self._root_node_id()
                else:
                    parent_node_id = dest
            else:
                parent_node_id = folder_node_ids[idx - 1]
            created_node = self._mkdir(name=directory_name,
                                       parent_node_id=parent_node_id)
            node_id = created_node['f'][0]['h']
            folder_node_ids[idx] = node_id
        return dict(zip(dirs, folder_node_ids.values()))

    def rename(self, file, new_name):
        file = file[1]
        # create new attribs
        attribs = {'n': new_name}
        # encrypt attribs
        encrypt_attribs = crypto.base64_url_encode(crypto.encrypt_attr(attribs, file['k']))
        encrypted_key = crypto.a32_to_base64(
            crypto.encrypt_key(file['key'], self.master_key)
        )
        # update attributes
        request = {
            'a': 'a',
            'attr': encrypt_attribs,
            'key': encrypted_key,
            'n': file['h'],
            'i': self.request_id
        }
        return self._api_request(request)

    def move(self, file_id, target):
        """
        Move a file to another parent node

        Params:
            file_id: the file to move.
            target: a node's id string, or one of the special nodes
                e.g. NODE_TYPE_TRASH, or the structure returned by find().
        """
        if isinstance(target, int):
            target_node_id = str(self.get_node_by_type(target)[0])

        elif isinstance(target, str):
            target_node_id = target

        elif isinstance(target, dict):
            target_node_id = target['h']

        elif isinstance(target, tuple):
            target_node_id = target[1]['h']

        else:
            raise TypeError(target)

        request = {
            'a': 'm',
            'n': file_id,
            't': target_node_id,
            'i': self.request_id
        }
        return self._api_request(request)

    def add_contact(self, email):
        """
        Add another user to your mega contact list
        """
        return self._edit_contact(email, True)

    def remove_contact(self, email):
        """
        Remove a user to your mega contact list
        """
        return self._edit_contact(email, False)

    def _edit_contact(self, email, add):
        """
        Editing contacts
        """
        if add is True:
            l = '1'  # add command
        elif add is False:
            l = '0'  # remove command
        else:
            raise errors.ValidationError('add parameter must be of type bool')

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise errors.ValidationError('add_contact requires a valid email address')
        else:
            request = {
                'a': 'ur',
                'u': email,
                'l': l,
                'i': self.request_id
            }
            return self._api_request(request)

    def get_public_url_info(self, url):
        """
        Dispatch to get_public_folder_info and get_public_file_info.
        """
        (public_handle, decryption_key) = self._parse_url(url)
        if '/#F!' in url:
            return self.get_public_folder_info(public_handle, decryption_key)
        else:
            return self.get_public_file_info(public_handle, decryption_key)

    def import_public_url(self, url, dest_node=None, dest_name=None):
        """
        Import the public url into user account
        """
        (public_handle, decryption_key) = self._parse_url(url)
        if '/#F!' in url:
            return self.import_public_folder(
                public_handle,
                decryption_key,
                dest_node=dest_node,
                dest_name=dest_name
            )
        else:
            return self.import_public_file(
                public_handle,
                decryption_key,
                dest_node=dest_node,
                dest_name=dest_name
            )

    def get_public_folder_files(self, folder_handle):
        # At the moment, the returned files will not have a decrypted 'a'.
        # TODO: cross-reference process_files code and figure out how to
        # decrypt them
        return self.get_files(public_folder_handle=folder_handle)

    def get_public_folder_info(self, folder_handle, folder_key):
        """
        Get the total size of a public folder.
        """
        # At the moment, the key is not actually needed. However if we decide
        # to extract more statistics, then we may need it and I'd rather not
        # change the function interface when that happens. So let's just take
        # the key now even though it does nothing.
        files = self.get_public_folder_files(folder_handle).values()
        size = sum(file['s'] for file in files if file['t'] == NODE_TYPE_FILE)
        return {'size': size}

    def import_public_folder(
        self, folder_handle, folder_key, dest_node=None, dest_name=None
    ):
        if dest_node is None:
            dest_node = self.get_node_by_type(NODE_TYPE_ROOT)[1]['h']
        elif isinstance(dest_node, int):
            dest_node = self.get_node_by_type(dest_node)[1]
        elif isinstance(dest_node, dict):
            dest_node = dest_node['h']
        elif isinstance(dest_node, str):
            pass
        else:
            raise TypeError(f'Invalid dest_node {dest_node}.')

        folder_key = crypto.base64_to_a32(folder_key)

        nodes = self.get_public_folder_files(folder_handle)

        # For all files and folders in the public folder, their 'p' will
        # correspond to the 'h' of either the public folder, or some nested
        # folder within. But, the public folder itself will have a 'p' that
        # does not correspond to any 'h'.  In this first loop, we gather the
        # 'h' of all folders, so that in the next loop we can tell if we are
        # processing the root folder by checking that its 'p' is not a known
        # folder's 'h'.
        folder_ids = set()
        for node in nodes:
            if node['t'] == NODE_TYPE_DIR:
                folder_ids.add(node['h'])

        import_list = []
        for node in nodes:
            k = node['k'].split(':')[1]
            k = crypto.decrypt_key(crypto.base64_to_a32(k), folder_key)
            new_k = crypto.a32_to_base64(crypto.encrypt_key(k, self.master_key))

            node_import_args = {
                'h': node['h'],
                'k': new_k,
                't': node['t'],
            }

            if node['p'] not in folder_ids:
                # This is the root public folder.
                if dest_name is not None:
                    new_a = {'n': dest_name}
                    new_a = crypto.base64_url_encode(crypto.encrypt_attr(new_a, k))
                    node_import_args['a'] = new_a
                else:
                    node_import_args['a'] = node['a']

                # The root should not have a 'p' argument.

            else:
                node_import_args['a'] = node['a']
                node_import_args['p'] = node['p']

            import_list.append(node_import_args)

        request = {
            'a': 'p',
            't': dest_node,
            'n': import_list,
            'v': 3,
            'i': self.request_id,
            'sm': 1,
        }
        return self._api_request(request)

    def get_public_file_info(self, file_handle, file_key):
        """
        Get size and name of a public file.
        """
        data = self._api_request({'a': 'g', 'p': file_handle, 'ssm': 1})
        if isinstance(data, int):
            raise errors.RequestError(data)

        if 'at' not in data or 's' not in data:
            raise ValueError("Unexpected result", data)

        key = crypto.base64_to_a32(file_key)
        k = crypto.interleave_xor_8(key)

        size = data['s']
        unencrypted_attrs = crypto.decrypt_attr(crypto.base64_url_decode(data['at']), k)
        if not unencrypted_attrs:
            return None
        result = {'size': size, 'name': unencrypted_attrs['n']}
        return result

    def import_public_file(self,
                           file_handle,
                           file_key,
                           dest_node=None,
                           dest_name=None):
        """
        Import the public file into user account
        """
        # Providing dest_node spare an API call to retrieve it.
        if dest_node is None:
            dest_node = self.get_node_by_type(NODE_TYPE_ROOT)[1]

        # Providing dest_name spares an API call to retrieve it.
        if dest_name is None:
            pl_info = self.get_public_file_info(file_handle, file_key)
            dest_name = pl_info['name']

        key = crypto.base64_to_a32(file_key)
        k = crypto.interleave_xor_8(key)
        encrypted_key = crypto.a32_to_base64(crypto.encrypt_key(key, self.master_key))
        encrypted_name = crypto.base64_url_encode(crypto.encrypt_attr({'n': dest_name}, k))
        request = {
            'a': 'p',
            't': dest_node['h'],
            'n': [
                {
                    'ph': file_handle,
                    't': NODE_TYPE_FILE,
                    'a': encrypted_name,
                    'k': encrypted_key
                }
            ]
        }
        return self._api_request(request)
