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

class RequestDraft:
    def __init__(self, request, finalize):
        self.request = request
        self.finalize = finalize

class Mega:
    def __init__(self):
        self.schema = 'https'
        self.domain = 'mega.co.nz'
        self.timeout = 160
        self.sid = None
        self.sequence_num = crypto.random_a32(length=1)[0]
        self.request_id = crypto.make_id(10)
        self._cached_trash_folder_node_id = None
        self._cached_root_node_id = None
        self.shared_keys = {}
        self.requests_session = requests.Session()

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type((errors.EAGAIN, json.decoder.JSONDecodeError)),
        stop=tenacity.stop_after_attempt(10),
        wait=tenacity.wait_exponential(multiplier=2, min=2, max=60),
        reraise=True,
    )
    def _api_request(self, request_data, params={}):
        request_params = {'id': self.sequence_num}
        self.sequence_num += 1

        if self.sid:
            request_params['sid'] = self.sid

        request_params.update(params)

        # ensure input data is a list
        if not isinstance(request_data, list):
            request_data = [request_data]

        request_json = [d.request if isinstance(d, RequestDraft) else d for d in request_data]

        logger.debug('API request: %s', request_json)

        response = self.requests_session.post(
            url=f'{self.schema}://g.api.{self.domain}/cs',
            params=request_params,
            data=json.dumps(request_json),
            timeout=self.timeout,
        )
        responses = json.loads(response.text)

        logger.debug('API response: %s', response.text[:250])

        if isinstance(responses, int):
            # If this raises EAGAIN it'll be caught by tenacity retry.
            raise errors.error_for_code(responses)

        if len(request_data) != len(responses):
            message = 'Number of requests and responses don\'t match.'
            message += f' {len(request_data)} != {len(responses)}.'
            raise errors.RequestError(message)

        if len(responses) == 1:
            request = request_data[0]
            response = responses[0]

            if response == 0:
                return response

            elif isinstance(response, int):
                # If this raises EAGAIN it'll be caught by tenacity retry.
                raise errors.error_for_code(response)

            elif isinstance(request, RequestDraft):
                response = request.finalize(response)

            return response

        final_response = []
        for (request, response) in zip(request_data, responses):
            if response == 0:
                pass

            elif isinstance(responses, int):
                response = errors.error_for_code(response)

            elif isinstance(request, RequestDraft):
                response = request.finalize(response)

            final_response.append(response)

        return final_response

    # CACHED SPECIAL NODES #########################################################################

    @property
    def _root_node_id(self):
        if self._cached_root_node_id is None:
            self._cached_root_node_id = self.get_node_by_type(NODE_TYPE_ROOT)[0]
        return self._cached_root_node_id

    @property
    def _trash_folder_node_id(self):
        if self._cached_trash_folder_node_id is None:
            self._cached_trash_folder_node_id = self.get_node_by_type(NODE_TYPE_TRASH)[0]
        return self._cached_trash_folder_node_id

    # LOGIN & REGISTER #############################################################################

    def _api_account_version_and_salt(self, email):
        '''
        The `us0` request returns a dictionary like
        {'v': 1} if the account is a v1 account, or
        {'v': 2, 's': '*salt*'} if the account is v2 or higher.

        This function will return a tuple (version, salt) where salt is None
        if the version is 1.
        '''
        resp = self._api_request({'a': 'us0', 'user': email})
        account_version = resp['v']
        user_salt = resp.get('s', None)
        return (account_version, user_salt)

    def _api_start_session(self, user, user_hash=None):
        '''
        The `us` request returns a dictionary like
        {
            'tsid': 'session' (if temporary session),
            'csid': 'session' (if login session),
            'privk': 'private key' (which must be decoded),
            'k': 'master key' (which must be decoded),
            'u': 'user id',
            'ach': 1 (I don't know, it's always 1 for me)
        }
        '''
        request = {'a': 'us', 'user': user}
        if user_hash is not None:
            request['uh'] = user_hash
        resp = self._api_request(request)
        return resp

    def login(self, email=None, password=None):
        if email:
            self.login_user(email, password)
        else:
            self.login_anonymous()
        logger.info('Login complete')
        return self

    def login_user(self, email, password):
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
            password_key = crypto.str_to_a32(pbkdf2_key[:16])
            user_hash = crypto.base64_url_encode(pbkdf2_key[-16:])
        else:
            password_a32 = crypto.str_to_a32(password)
            password_key = crypto.prepare_key(password_a32)
            user_hash = crypto.stringhash(email, password_key)

        resp = self._api_start_session(email, user_hash)
        self._login_process(resp, password_key)

    def login_anonymous(self, password=None):
        logger.info('Logging in anonymous temporary user...')
        master_key = crypto.random_a32(length=4)

        # During the registration process, we start an anonymous session that
        # will become our account. This is why we can choose a password here.
        if password is None:
            password_key = crypto.random_a32(length=4)
        else:
            password_a32 = crypto.str_to_a32(password)
            password_key = crypto.prepare_key(password_a32)

        session_self_challenge = crypto.random_a32(length=4)

        k = crypto.a32_to_base64(crypto.encrypt_key(master_key, password_key))
        ts = crypto.a32_to_str(session_self_challenge)
        ts += crypto.a32_to_str(crypto.encrypt_key(session_self_challenge, master_key))
        ts = crypto.base64_url_encode(ts)
        user = self._api_request({'a': 'up', 'k': k, 'ts': ts})

        resp = self._api_start_session(user)
        self._login_process(resp, password_key)

    def register(self, email, password, name=''):
        self.login_anonymous(password=password)
        self._api_request({'a': 'up', 'name': name})

        # Request signup link
        challenge = tuple(crypto.random_a32(length=4))
        cdata = self.master_key + challenge
        request = {
            'a': 'uc',
            'c': crypto.a32_to_base64(cdata),
            'n': crypto.base64_url_encode(name.encode('utf-8')),
            'm': crypto.base64_url_encode(email.encode('utf-8')),
        }
        self._api_request(request)
        self._registration_challenge = challenge

    def verify_registration(self, confirmation):
        if not hasattr(self, '_registration_challenge'):
            message = 'You cannot call verify_registration before calling register.'
            raise errors.RegistrationError(message)

        confirmation = confirmation.split('/#confirm', 1)[-1]

        request = {
            'a': 'ud',
            'c': confirmation,
        }
        response = self._api_request(request)
        (email, name, user_id, encrypted_key, challenge) = response

        email = crypto.base64_url_decode(email).decode('utf-8').lower()
        challenge = crypto.base64_to_a32(challenge)

        if challenge != self._registration_challenge:
            message = f'local: {self._registration_challenge}, remote: {challenge}.'
            raise errors.RegistrationChallengeFailed(message)

        user_hash = crypto.stringhash(email, self._password_key)

        self._api_request({'a': 'up', 'uh': user_hash, 'c': confirmation})
        response = self._api_start_session(email, user_hash)
        self._login_process(response, self._password_key)

        private = RSA.generate(2048)
        public = private.publickey()

        pubk = crypto.base64_url_encode(crypto.int_to_mpi(public.n) + crypto.int_to_mpi(public.e))
        privk = b''.join([
            crypto.int_to_mpi(private.p),
            crypto.int_to_mpi(private.q),
            crypto.int_to_mpi(private.d),
            crypto.int_to_mpi(private.u),
        ])
        padding = (len(privk) % 16) % 16
        privk += b'\x00' * padding
        privk = crypto.str_to_a32(privk)
        privk = crypto.encrypt_key(privk, self.master_key)
        privk = crypto.a32_to_base64(privk)
        request = {
            'a': 'up',
            'pubk': pubk,
            'privk': privk,
        }
        self._api_request(request)

    def _login_process(self, resp, password_key):
        encrypted_master_key = crypto.base64_to_a32(resp['k'])
        self._password_key = password_key
        self.master_key = crypto.decrypt_key(encrypted_master_key, password_key)
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
                bit_length = (private_key[0] * 256) + private_key[1]
                byte_length = math.ceil(bit_length / 8)
                # Add 2 bytes to accommodate the MPI header
                byte_length += 2
                rsa_private_key[i] = crypto.mpi_to_int(private_key[:byte_length])
                private_key = private_key[byte_length:]

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

    # HELPER METHODS ###############################################################################

    def get_id_from_obj(self, node_data):
        '''
        Get node id from a file object
        '''
        node_id = None

        for i in node_data['f']:
            if i['h'] != '':
                node_id = i['h']
        return node_id

    def normalize_node(self, node):
        if isinstance(node, dict):
            return node
        if isinstance(node, int):
            return self.get_node_by_type(node)[1]

    def normalize_node_id(self, node):
        if node is None:
            return self._root_node_id
        elif isinstance(node, int):
            return self.get_node_by_type(node)[1]['h']
        elif isinstance(node, dict):
            return node['h']
        elif isinstance(node, str):
            return node
        else:
            raise TypeError(f'Invalid node {node}.')

    def parse_url(self, url):
        '''
        Given a url like 'https://mega.nz/#!fileid!filekey', return a tuple
        (fileid, filekey).
        '''
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

    # CONTACTS #####################################################################################

    def _draft_add_remove_contact(self, email, add):
        if not isinstance(add, bool):
            raise errors.ValidationError(f'`add` must be of type bool, not {type(add)}.')

        l = '1' if add else '0'

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise errors.ValidationError('add_contact requires a valid email address')

        request = {
            'a': 'ur',
            'u': email,
            'l': l,
            'i': self.request_id
        }
        return request

    def draft_add_contact(self, email):
        '''
        Add a user to your mega contact list.
        '''
        return self._draft_add_remove_contact(email, True)

    def final_add_contact(self, response):
        return response

    def add_contact(self, *args, **kwargs):
        request = self.draft_add_contact(*args, **kwargs)
        draft = RequestDraft(request, self.final_add_contact)
        return self._api_request(draft)

    def draft_remove_contact(self, email):
        '''
        Remove a user from your mega contact list.
        '''
        return self._draft_add_remove_contact(email, False)

    def final_remove_contact(self, response):
        return response

    def remove_contact(self, *args, **kwargs):
        request = self.draft_remove_contact(*args, **kwargs)
        draft = RequestDraft(request, self.final_remove_contact)
        return self._api_request(draft)

    # CREATE FOLDER ################################################################################

    def _mkdir(self, name, parent_node_id):
        # generate random aes key (128) for folder
        ul_key = crypto.random_a32(length=6)

        # encrypt attribs
        attribs = {'n': name}
        encrypt_attribs = crypto.base64_url_encode(crypto.encrypt_attr(attribs, ul_key[:4]))
        encrypted_key = crypto.a32_to_base64(crypto.encrypt_key(ul_key[:4], self.master_key))

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

    def create_folder(self, name, dest=None):
        dirs = tuple(dir_name for dir_name in str(name).split('/') if dir_name)
        folder_node_ids = {}
        if dest is None:
            folder_node_ids[-1] = dest
        else:
            folder_node_ids[-1] = self._root_node_id

        for (index, directory_name) in enumerate(dirs):
            existing_node_id = self.find_path_descriptor(directory_name)
            if existing_node_id:
                folder_node_ids[index] = existing_node_id
                continue
            parent_node_id = folder_node_ids[index - 1]
            created_node = self._mkdir(
                name=directory_name,
                parent_node_id=parent_node_id,
            )
            node_id = created_node['f'][0]['h']
            folder_node_ids[index] = node_id
        folder_node_ids.pop(-1)

        return dict(zip(dirs, folder_node_ids.values()))

    # DESTROY ######################################################################################

    def draft_destroy_file(self, file_id):
        request = {
            'a': 'd',
            'n': file_id,
            'i': self.request_id
        }
        return RequestDraft(request, self.final_destroy)

    def final_destroy_file(self, response):
        return response

    def destroy_file(self, *args, **kwargs):
        '''
        Completely delete a file by its file id.
        '''
        return self._api_request(self.draft_destroy(*args, **kwargs))

    def destroy_url(self, url):
        '''
        Destroy a file by its public url.
        Because this relies on the get_id_from_public_handle endpoint to
        work, this function does not offer drafts
        '''
        (public_handle, decryption_key) = self.parse_url(url)
        file_id = self.get_id_from_public_handle(public_handle)
        return self.destroy(file_id)

    def destroy_urls(self, urls):
        '''
        Destroy multiple files by their public urls.
        Because this relies on the get_id_from_public_handle endpoint to
        work, this function does not offer drafts and will take care of
        batching by itself.
        '''
        parseds = [self.parse_url(url) for url in urls]
        requests = [self.draft_get_id_from_public_handle(handle) for (handle, key) in parseds]
        file_ids = self._api_request(requests)
        requests = [self.draft_destroy(file_id) for file_id in file_ids]
        return self._api_request(requests)

    # DOWNLOAD #####################################################################################

    def _download_file(
            self,
            file_handle,
            file_key,
            dest_path=None,
            dest_filename=None,
            is_public=False,
            file=None,
        ):
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

        input_file = self.requests_session.get(file_url, stream=True).raw

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

    def download_file(self, file, dest_path=None, dest_filename=None):
        '''
        Download a file by its file object
        '''
        return self._download_file(
            file_handle=None,
            file_key=None,
            file=file[1],
            dest_path=dest_path,
            dest_filename=dest_filename,
            is_public=False,
        )

    def download_url(self, url, dest_path=None, dest_filename=None):
        '''
        Download a file by its public url
        '''
        (public_handle, decryption_key) = self.parse_url(url)
        return self._download_file(
            file_handle=public_handle,
            file_key=decryption_key,
            dest_path=dest_path,
            dest_filename=dest_filename,
            is_public=True,
        )

    # EMPTY TRASH ##################################################################################

    def empty_trash(self):
        '''
        Because this relies on get_files_in_node, this method does not offer
        drafts.
        '''
        files = self.get_files_in_node(self._trash_folder_node_id)

        if not files:
            return

        drafts = [self.draft_destroy(file) for file in files]
        return self._api_request(drafts)

    # EXPORT #######################################################################################

    def export_file(self, node):
        return self.export_files([node])

    def export_files(self, nodes):
        nodes = [self.normalize_node(node) for node in nodes]
        request = [{'a': 'l', 'n': node['h'], 'i': self.request_id} for node in nodes]
        self._api_request(request)
        request = [self.draft_get_file_link(node) for node in nodes]
        response = self._api_request(request)
        # When there's only one file
        if isinstance(response, str) and response.startswith('https://mega'):
            response = [response]
        url_map = {node['h']: url for (node, url) in zip(nodes, response)}
        return url_map

    ################################################################################################

    def export_folder(self, node):
        '''
        Because this relies on get_files, this function does not offer drafts.
        '''
        node = self.normalize_node(node)

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
        request = {
            'a': 's2',
            'n': node_id,
            's': [{
                'u': 'EXP',
                'r': 0
            }],
            'i': self.request_id,
            'ok': ok,
            'ha': ha,
            'cr': [[node_id], [node_id], [0, 0, encrypted_node_key]]
        }
        node_id = self._api_request(request)
        nodes = self.get_files()
        return nodes[node_id]

    # FIND #########################################################################################

    def find(self, filename=None, handle=None, exclude_deleted=False):
        '''
        Return file object from given filename
        '''
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
                    parent_node_id = self.find_path_descriptor(
                        parent_dir_name,
                        files=files,
                    )
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

    def find_path_descriptor(self, path, files=()):
        '''
        Find descriptor of folder inside a path. i.e.: folder1/folder2/folder3
        Params:
            path: string like 'folder1/folder2/folder3'
        Return:
            Descriptor (str) of folder3 if exists, None otherwise
        '''
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

    # GET BALANCE ##################################################################################

    def draft_get_balance(self):
        '''
        Get account monetary balance, Pro accounts only
        '''
        request = {"a": "uq", "pro": 1}
        return RequestDraft(request, self.final_get_balance)

    def final_get_balance(self, response):
        if 'balance' in response:
            return response['balance']

    def get_balance(self, *args, **kwargs):
        return self._api_request(self.draft_get_balance(*args, **kwargs))

    # GET FILE LINK ################################################################################

    def draft_get_file_link(self, file):
        '''
        Get public link from given file object.
        '''
        file = self.normalize_node(file)

        if not ('h' in file and 'k' in file):
            raise errors.ValidationError('File id and key must be present')

        request = {'a': 'l', 'n': file['h']}
        return RequestDraft(request, lambda response: self.final_get_file_link(response, file))

    def final_get_file_link(self, response, file):
        if response == -11:
            raise errors.RequestError(
                "Can't get a public link from that file "
                "(is this a shared file?)"
            )

        public_handle = response
        decrypted_key = crypto.a32_to_base64(file['key'])
        url = f'{self.schema}://{self.domain}/#!{public_handle}!{decrypted_key}'
        return url

    def get_file_link(self, *args, **kwargs):
        return self._api_request(self.draft_get_file_link(*args, **kwargs))

    # GET FILES ####################################################################################

    def _init_shared_keys(self, files):
        '''
        Init shared key not associated with a user.
        Seems to happen when a folder is shared,
        some files are exchanged and then the
        folder is un-shared.
        Keys are stored in files['s'] and files['ok']
        '''
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
            if isinstance(processed_file['a'], dict):
                files_dict[file['h']] = processed_file
            else:
                logger.warning('%s\'s attributes were not decrypted.', file['h'])
        self._nodes = files_dict
        return files_dict

    def get_files_in_node(self, target):
        '''
        Get all files in a given target.
        Params:
            target: a node's id string, or one of the special nodes
                e.g. NODE_TYPE_TRASH.
        '''
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

    # GET FOLDER LINK ##############################################################################

    def draft_get_folder_link(self, file):
        file = self.normalize_node(file)

        if not ('h' in file and 'k' in file):
            raise errors.ValidationError('File id and key must be present')

        request = {'a': 'l', 'n': file['h']}
        return RequestDraft(request, lambda response: self.final_get_folder_link(response, file))

    def final_get_folder_link(self, response, file):
        # THIS WILL NEVER HAPPEN DUE TO RAISE BY CODE.
        if response == -11:
            raise errors.RequestError(
                "Can't get a public link from that folder "
                "(is this a shared folder?)"
            )

        public_handle = response
        decrypted_key = crypto.a32_to_base64(file['shared_folder_key'])
        return (
            f'{self.schema}://{self.domain}/#F!{public_handle}!{decrypted_key}'
        )

    def get_folder_link(self, *args, **kwargs):
        return self._api_request(self.draft_get_folder_link(*args, **kwargs))

    # GET ID FROM HANDLE ###########################################################################

    def draft_get_id_from_public_handle(self, public_handle):
        request = {'a': 'f', 'f': 1, 'p': public_handle}
        return RequestDraft(request, self.final_get_id_from_public_handle)

    def final_get_id_from_public_handle(self, response):
        node_id = self.get_id_from_obj(response)
        return node_id

    def get_id_from_public_handle(self, *args, **kwargs):
        return self._api_request(self.draft_get_id_from_public_handle(*args, **kwargs))

    # GET NODE BY TYPE #############################################################################

    def get_node_by_type(self, type):
        '''
        Get a node by it's numeric type id, e.g:
        2: special: root cloud drive
        3: special: inbox
        4: special: trash bin
        '''
        # Should we also check for NODE_TYPE_FILE, NODE_TYPE_DIR here?
        nodes = self.get_files()
        for node in list(nodes.items()):
            if node[1]['t'] == type:
                return node

    # GET PUBLIC FILE INFO #########################################################################

    def draft_get_public_file_info(self, file_handle, file_key):
        request = {'a': 'g', 'p': file_handle, 'ssm': 1}
        return RequestDraft(request, self.final_get_public_file_info)

    def final_get_public_file_info(self, response):
        data = response
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

    def get_public_file_info(self, *args, **kwargs):
        '''
        Get size and name of a public file.
        '''
        return self._api_request(self.draft_get_public_file_info(*args, **kwargs))

    # GET PUBLIC FOLDER INFO #######################################################################

    def get_public_folder_info(self, folder_handle, folder_key):
        '''
        Get the total size of a public folder.
        '''
        # At the moment, the key is not actually needed. However if we decide
        # to extract more statistics, then we may need it and I'd rather not
        # change the function interface when that happens. So let's just take
        # the key now even though it does nothing.
        files = self.get_public_folder_files(folder_handle).values()
        size = sum(file['s'] for file in files if file['t'] == NODE_TYPE_FILE)
        return {'size': size}

    def get_public_folder_files(self, folder_handle):
        # At the moment, the returned files will not have a decrypted 'a'.
        # TODO: cross-reference process_files code and figure out how to
        # decrypt them
        return self.get_files(public_folder_handle=folder_handle)

    # GET PUBLIC URL INFO ##########################################################################

    def get_public_url_info(self, url):
        '''
        Dispatch to get_public_folder_info and get_public_file_info.
        '''
        (public_handle, decryption_key) = self.parse_url(url)
        if '/#F!' in url:
            return self.get_public_folder_info(public_handle, decryption_key)
        else:
            return self.get_public_file_info(public_handle, decryption_key)

    # GET STORAGE QUOTA ############################################################################

    def draft_get_storage_quota(self):
        '''
        Get disk quota usage and maximum.
        '''
        request = {
            'a': 'uq',
            'strg': 1,
            'v': 1
        }
        return RequestDraft(request, self.final_get_storage_quota)

    def final_get_storage_quota(self, response):
        response = {
            'total': response['mstrg'],
            'used': response['cstrg'],
            'remaining': response['mstrg'] - response['cstrg'],
        }
        return response

    def get_storage_quota(self, *args, **kwargs):
        return self._api_request(self.draft_get_storage_quota(*args, **kwargs))

    # GET TRANSFER QUOTA ###########################################################################

    def draft_get_transfer_quota(self):
        '''
        Get transfer quota usage and maximum.
        '''
        request = {
            'a': 'uq',
            'xfer': 1,
            'v': 1
        }
        return RequestDraft(request, self.final_get_transfer_quota)

    def final_get_transfer_quota(self, response):
        if response['utype'] == 0:
            # For free accounts, there is no specified limit and your bandwidth
            # is  measured in a 6-hour rolling window.
            response = {
                'total': None,
                'used': sum(response['tah']),
                'remaining': None,
            }
        else:
            # For Pro users, bandwidth limits are clearly defined by the
            # account  and the response contains simple integers for total, used.
            response = {
                'total': response['mxfer'],
                'used': response['caxfer'],
                'remaining': response['mxfer'] - response['caxfer'],
            }
        return response

    def get_transfer_quota(self, *args, **kwargs):
        return self._api_request(self.draft_get_transfer_quota(*args, **kwargs))

    # GET FILE LINK FROM UPLOAD ####################################################################

    def get_upload_link(self, file):
        '''
        Get a file's public link including decryption key
        Requires upload() response as input
        '''
        if 'f' in file:
            file = file['f'][0]
            public_handle = self._api_request({'a': 'l', 'n': file['h']})
            file_key = file['k'][file['k'].index(':') + 1:]
            decrypted_key = crypto.a32_to_base64(
                crypto.decrypt_key(crypto.base64_to_a32(file_key), self.master_key)
            )
            return f'{self.schema}://{self.domain}/#!{public_handle}!{decrypted_key}'
        else:
            raise ValueError('''Upload() response required as input,
                            use get_links() for regular file input''')

    # GET USER INFO ################################################################################

    def draft_get_user(self):
        request = {'a': 'ug'}
        return RequestDraft(request, self.final_get_user)

    def final_get_user(self, response):
        return response

    def get_user(self, *args, **kwargs):
        return self._api_request(self.draft_get_user(*args, **kwargs))

    # IMPORT PUBLIC FILE ###########################################################################

    def draft_import_public_file(
            self,
            file_handle,
            file_key,
            dest_node=None,
            dest_name=None,
        ):
        # Providing dest_node spares an API call to retrieve it.
        dest_node = self.normalize_node_id(dest_node)

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
            't': dest_node,
            'n': [
                {
                    'ph': file_handle,
                    't': NODE_TYPE_FILE,
                    'a': encrypted_name,
                    'k': encrypted_key
                }
            ]
        }
        return RequestDraft(request, self.final_import_public_file)

    def final_import_public_file(self, response):
        return response

    def import_public_file(self, *args, **kwargs):
        '''
        Import the public file into user account
        '''
        return self._api_request(self.draft_import_public_file(*args, **kwargs))

    # IMPORT PUBLIC FOLDER #########################################################################

    def draft_import_public_folder(
            self,
            folder_handle,
            folder_key,
            dest_node=None,
            dest_name=None,
        ):
        dest_node = self.normalize_node_id(dest_node)

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
        return RequestDraft(request, self.final_import_public_folder)

    def final_import_public_folder(self, response):
        return response

    def import_public_folder(self, *args, **kwargs):
        return self._api_request(self.draft_import_public_folder(*args, **kwargs))

    # IMPORT PUBLIC URL ############################################################################

    def draft_import_public_url(self, url, dest_node=None, dest_name=None):
        (public_handle, decryption_key) = self.parse_url(url)
        if '/#F!' in url:
            return self.draft_import_public_folder(
                public_handle,
                decryption_key,
                dest_node=dest_node,
                dest_name=dest_name
            )
        else:
            return self.draft_import_public_file(
                public_handle,
                decryption_key,
                dest_node=dest_node,
                dest_name=dest_name
            )

    def final_import_public_url(self, response):
        return response

    def import_public_url(self, *args, **kwargs):
        '''
        Import the public url into user account
        '''
        return self._api_request(self.draft_import_public_url(*args, **kwargs))

    # MOVE FILES ###################################################################################

    def draft_move(self, file_id, target):
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
        return RequestDraft(request, self.final_move)

    def final_move(self, response):
        return response

    def move(self, *args, **kwargs):
        '''
        Move a file to another parent node

        Params:
            file_id: the file to move.
            target: a node's id string, or one of the special nodes
                e.g. NODE_TYPE_TRASH, or the structure returned by find().
        '''
        return self._api_request(self.draft_move(*args, **kwargs))

    # RECYCLE FILE #################################################################################

    def draft_recycle_file(self, file_id):
        return self.draft_move(file_id, self._trash_folder_node_id)

    def final_recycle_file(response):
        return response

    def recycle_file(self, *args, **kwargs):
        '''
        Move a file to the rubbish bin by its file id.
        '''
        return self._api_request(self.draft_recycle_file(*args, **kwargs))

    def recycle_url(self, url):
        '''
        Move a file to the rubbish bin by its public url.
        Because this relies on the get_id_from_public_handle endpoint to
        work, this method does not offer drafts.
        '''
        (public_handle, decryption_key) = self.parse_url(url)
        file_id = self.get_id_from_public_handle(public_handle)
        return self.move(file_id, self._trash_folder_node_id)

    def recycle_urls(self, urls):
        '''
        Move multiple files to the rubbish bin by their public urls.
        Because this relies on the get_id_from_public_handle endpoint to
        work, this method does not offer drafts and will take care of
        batching by itself.
        '''
        parseds = [self.parse_url(url) for url in urls]
        requests = [self.draft_get_id_from_public_handle(handle) for (handle, key) in parseds]
        file_ids = self._api_request(requests)
        requests = [self.draft_move(file_id) for file_id in file_ids]
        return self._api_request(requests)

    # RENAME FILE ##################################################################################

    def draft_rename(self, file, new_name):
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
        return RequestDraft(request, self.final_rename)

    def final_rename(self, response):
        return response

    def rename(self, *args, **kwargs):
        return self._api_request(self.draft_rename(*args, **kwargs))

    # UPLOAD #######################################################################################

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
            ul_key = crypto.random_a32(length=6)
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
                    output_file = self.requests_session.post(
                        ul_url + "/" + str(chunk_start),
                        data=chunk,
                        timeout=self.timeout
                    )
                    completion_file_handle = output_file.text
                    logger.info('%s of %s uploaded', upload_progress,
                                file_size)
            else:
                output_file = self.requests_session.post(
                    ul_url + "/0",
                    data='',
                    timeout=self.timeout
                )
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
