from .encdec import Encryption
from qpylib import qpylib
import json
import os

config_path = qpylib.get_store_path('legacy_secret_e.db')

try:
    encryption_available = Encryption.encryption_available
except:
    encryption_available = False

def get_secret(secret_name):
    """ Function to make getting a secret easy
    :param secret_name: the name / key for the secret. Ex: xfe_api_token
    :param sec_token: (Optional) used to indicate the fallback method was the"""
    data = {
        "name": secret_name,
        "user": "simple_secret_user"
    }

    # If we're on a platform with no encryption available, don't even try since it will break
    if encryption_available:

        secret_engine = Encryption(data)

        if secret_engine.saved_secret_version() == Encryption.engine_version:
            return secret_engine.decrypt()

        elif secret_engine.saved_secret_version() == 2:
            from .oldencdec.encdecv2 import Encryption as Encryption_v2
            return _upgrade_secret(Encryption_v2(data), secret_engine)

        else:
            # Now we need to go to the ultimate fallback, we pass this to some additional handling
            secret_value = _get_fallback(data)
            secret_engine.encrypt(secret_value)
            qpylib.log('encdec : _upgrade_secret : Upgraded secret: {0}'.format(secret_engine.secret_name()))
    else:
        _get_fallback(data


def _upgrade_secret(old_secret_engine, current_secret_engine):
    """ Wrapper so we don't have to """
    secret_value = old_secret_engine.decrypt()
    current_secret_engine.encrypt(secret_value)
    qpylib.log('encdec : _upgrade_secret : Upgraded secret: {0}'.format(current_secret_engine.secret_name()))
    return secret_value



def put_secret(secret_name, secret_value):
    """ Function to make saving a secret easy
    :param secret_name: the name / key for the secret. Ex: xfe_api_token
    :param secret_value: the actual secret. Ex: abjdf893-djbvds"""
    data = {
        "name": secret_name,
        "user": "simple_secret_user"
    }


    if encryption_available:
        secret_engine = Encryption({
            "name":secret_name,
            "user":"simple_secret_user"})
        return secret_engine.encrypt(secret_value)
    else:
        _put_fallback(data,secret_value)

def _get_fallback(data, sec_token):
    return __load_conf(config_path)[data['name']]

def _put_fallback(secret_value):
    conf = __load_conf(config_path)
    conf['data'] = secret_value
    __save_config(config_path, conf)

def __save_config(config):
    """ Writes the config object to a file on disk """
    try:
        with open(config_path, 'w') as config_file:
            config_file.write(json.dumps(config))

    except Exception as error:  # pylint: disable=W0703
        qpylib.log('encdec : __save_config : Error saving Encryption config file: {0}'.format(str(error)))


def __load_conf():
    """ Loads config file from the disk to get needed hashes
        if config doesnt exists creates it.
    """
    try:
        with open(config_path) as config_file:
            config = json.load(config_file)
        return config

    except IOError as error:
        qpylib.log('encdec : __load_conf : Encryption conf file : {0} does not exist, creating'.format(str(error)))


    except Exception as error:  # pylint: disable=W0703
        qpylib.log('encdec : __load_conf : Error reading Encryption conf file {0}'.format(str(error)))

def migrate_from_v1(user_dict, sec_token):
    """ This is designed to be run once at app startup to migrate old v1
    passwords to a newer format
    :param user_dict should be a dict with the user as the key, and the value
    as an array of names (the secret names). After migrating we overwrite the old secret.
    Example:
    {
    "xfe":["token", "password"],
    "qradar": ["sec_token"]
    }
    """
    from .oldencdec.encdecv1 import Encryption as Encryptionv1

    for user in user_dict:
        config_path = qpylib.get_store_path(str(user) + '_e.db')
        if os.path.isfile(config_path):
            for name in user_dict[user]:
                data = {
                    "name": name,
                    "user": user,
                    "sec_token": sec_token
                }
                old_secret = Encryptionv1(data)
                secret_value = old_secret.decrypt()
                put_secret(name, secret_value)
                qpylib.log('encdec : migrate_from_v1 : Upgraded secret: {0}'.format(name))
                #This part overwrites the secrets stored in Qradar
                old_secret.encrypt("this_is_nothing_now")
            #This removes the old secret files so we won't hit it again
            os.remove(config_path)







