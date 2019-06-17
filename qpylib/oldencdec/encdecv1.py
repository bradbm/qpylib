#!/bin/python
"""
That files used to create a random salt and encrypt, decrypt strings with it
That file should stay off the app folder. We shouldnt distribute this file.
"""

import json
import random
import string
import binascii

from qpylib import qpylib
from requests import get, post
from urllib import urlencode

from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Protocol import KDF


class Encryption(object):

    """ Encryption Logic """

    def __init__(self, data):
        if 'name' not in data or 'sec_token' not in data or 'user' not in data \
                or data['name'] == '' or data['sec_token'] == '':
            raise ValueError("Encryption : sec_token, a name and user are mandatory fields!")
        self.sec_token = data['sec_token']
        self.name = data['name']
        self.user_id = data['user']
        self.api_url = 'https://' + qpylib.get_console_address()
        self.headers = {'SEC': self.sec_token, 'Version': '5.1'}
        self.config_path = qpylib.get_store_path(str(self.user_id) + '_e.db')
        self.kim = ''
        self.config = {}
        self.__load_conf()

    def __init_config(self):
        """ Generates salt UUID and ivz to be used and saves them on a config"""
        self.config[self.name] = {}
        self.config[self.name]['salt'] = self.__generate_random()
        self.config[self.name]['UUID'] = self.__generate_token()
        self.config[self.name]['ivz'] = self.__generate_random()
        self.config[self.name]['secret'] = self.__generate_random()
        self.config[self.name]['iterations'] = random.randint(1500, 2000)
        self.__save()

    def __load_conf(self):
        """ Loads config file from the disk to get needed hashes
            if config doesnt exists creates it.
        """
        try:
            with open(self.config_path) as config_file:
                self.config = json.load(config_file)
                if self.name not in self.config:
                    self.__init_config()

        except IOError, error:
            qpylib.log('encdec : __load_conf : \
            Error reading Encryption conf file : {0}'.format(str(error)))
            self.__init_config()

        except Exception, error:  # pylint: disable=W0703
            qpylib.log('encdec : __load_conf : \
            Error reading Encryption conf file {0}'.format(str(error)))
            self.__init_config()

    def __save(self):
        """ Saves the config object to a file on disk """
        try:
            with open(self.config_path, 'w') as config_file:
                config_file.write(json.dumps(self.config))

        except IOError, error:
            qpylib.log(
                'encdec : __save : Error saving Encryption conf file: {0}'.format(error))

        except Exception, error:  # pylint: disable=W0703
            qpylib.log('encdec : __load_conf : \
            Error Saving Encrypted Encryption conf file {0}'.format(str(error)))

    def __generate_token(self):
        """ Generates a MD5 Token to be used as UUID at reference_data map name. """
        newMd5 = MD5.new(self.__generate_random()).hexdigest()
        if len(self.config) > 0:
            for name in self.config:
                if 'UUID' in self.config[name] and str(newMd5) == str(self.config[name]['UUID']):
                    newMd5 = self.__generate_token()
        return newMd5

    def __generate_random(self):
        """ Generates a random hash with letters, digits and special characters """
        random_hash = ''.join(
            (
                random.choice(
                    string.letters +
                    string.digits +
                    string.punctuation
                )
            )
            for x in range(16)
        )
        return random_hash

    def __encrypt_string(self, clear):
        """ Encrypts a string """
        aes = AES.new(
            self.__generate_dk(self.kim),
            AES.MODE_CFB,
            self.config[self.name]['ivz'],
            segment_size=128)
        plaintext = self.__pad_string(clear)
        encrypted_text = aes.encrypt(plaintext)
        return binascii.b2a_hex(encrypted_text).rstrip()

    def __decrypt_string(self, kim):
        """ Decrypts a string """
        aes = AES.new(
            self.__generate_dk(kim),
            AES.MODE_CFB,
            self.config[self.name]['ivz'],
            segment_size=128)
        encrypted_text_bytes = binascii.a2b_hex(self.config[self.name]['secret'])
        decrypted_text = aes.decrypt(encrypted_text_bytes)
        decrypted_text = self.__unpad_string(decrypted_text)
        return decrypted_text

    def __pad_string(self, value):
        """ Adds padding to the string """
        length = len(value)
        pad_size = 16 - (length % 16)
        return value.ljust(length + pad_size, '\x00')

    def __unpad_string(self, value):
        """ Removes the added padding from the string """
        while value[-1] == '\x00':
            value = value[:-1]
        return value

    def __get_key(self):
        """ Gets the encrypted key from the reference_data api. """
        return_val = {
            'status_code': 'unknown'
        }

        resp = get(
            self.api_url + '/api/reference_data/maps/' +
            self.config[self.name]['UUID'],
            headers=self.headers,
            verify=False,
            timeout=30
        )

        if resp.status_code == 401 or resp.status_code == 403:
            qpylib.log('encDec : __get_key : \
                Unauthorized Access. No Auth token or incorrect one: {0}'.format(resp.text))

            return_val['status_code'] = resp.status_code
        elif resp.status_code == 404:
            return_val['status_code'] = resp.status_code
        elif resp.status_code == 200 or resp.status_code == 200:
            return_val['status_code'] = resp.status_code
            response = resp.json()
            if 'data' in response:
                return_val['value'] = response['data']['key'][
                    'value']
            else:
                return_val['status_code'] = resp.status_code
        return return_val

    def __create_pass(self, raw, update):
        """ Saves/updates the key on the reference_data api """
        name = self.config[self.name]['UUID']

        if not update:
            create_map_response = post(
                self.api_url +
                '/api/reference_data/maps?element_type=ALN&name=' +
                self.config[self.name]['UUID'],
                headers=self.headers,
                verify=False,
                timeout=30
            )

            name = create_map_response.json()['name'] if create_map_response and \
                'name' in create_map_response.json() else None

        if name and name == self.config[self.name]['UUID']:
            qpylib.log('encDec : __create_pass : hash map created')

            self.kim = self.__generate_token()
            self.config[self.name]['secret'] = self.__encrypt_string(raw)

            payload = urlencode({'key': 'key', 'value': self.kim})

            create_val_response = post(
                self.api_url +
                '/api/reference_data/maps/' + name,
                params=payload,
                headers=self.headers,
                verify=False,
                timeout=30
            )
            self.__save()

            return self.config[self.name]['secret']

        else:
            qpylib.log('encDec : __create_pass : \
                Huh ? Maps name wasnt hash ?: {0}'.format(create_val_response.text))

            return False

    def __generate_dk(self, ikm):
        """
            Derive one key from a string ( we currently using a random one ).
        """
        return KDF.PBKDF2(ikm, self.config[self.name]['salt'], dkLen=16,
                          count=self.config[self.name]['iterations'])

    def encrypt(self, raw):
        """ Encrypts and save a clear password to the reference_data api """
        if raw.strip(' \t\n\r') == '':
            qpylib.log('encDec : encrypt : \
                    cant encrypt an empty string aborting...')
            return False
        try:
            resp = self.__get_key()

            if resp['status_code'] == 401 or resp['status_code'] == 403:
                qpylib.log('encDec : encrypt : \
                    Unauthorized Access. No Auth token or incorrect one')
                return False

            if resp['status_code'] == 404:
                qpylib.log('encDec : encrypt : \
                    I didnt find any hash key, i am creating one!')
                return self.__create_pass(raw, False)

            elif resp['status_code'] == 200 or resp['status_code'] == 200:
                return self.__create_pass(raw, True)

            else:
                qpylib.log('encDec : encrypt : \
                    Problem with the hash key we are returning an empty string for now')

                return str('')

        except Exception, error:  # pylint: disable=W0703
            qpylib.log('encDec : encrypt : \
                Verification of authentication token failed: {0}'.format(error))

            return str('')

    def decrypt(self):
        """
            Determines if there is a key in reference_data api,
            decrypting it and returning to the app
        """

        try:
            resp = self.__get_key()

            if resp['status_code'] == 401 or resp['status_code'] == 403:
                qpylib.log('encDec : decrypt : \
                    Unauthorized Access. No Auth token or incorrect one')
                return False

            if resp['status_code'] == 404:
                qpylib.log('encDec : decrypt : \
                    I didnt find any hash key, no pass set!')
                return str('')

            elif resp['status_code'] == 200 or resp['status_code'] == 200:
                return self.__decrypt_string(resp['value'])

            else:
                qpylib.log('encDec : decrypt : \
                    Problem with the hash key we are returning an empty string for now')

                return str('')

        except Exception, error:  # pylint: disable=W0703
            qpylib.log('encDec : decrypt : \
                Verification of authentication token failed: {0}'.format(error))

            return str('')
