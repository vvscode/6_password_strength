import getpass
import re
import urllib.request
import hashlib
from collections import Counter


def has_normal_length(password):
    return len(password) > 8


def has_perfect_length(password):
    return len(password) > 15


def contains_number(password):
    return re.search(r"\d", password) is not None


def contains_lowercase_letters(password):
    return re.search(r"[a-z]", password) is not None


def contains_uppercase_letters(password):
    return re.search(r"[A-Z]", password) is not None


def contains_non_alphanumeric(password):
    return re.search(r"[^a-zA-Z0-9]", password) is not None


def has_been_pwned(password):
    # https://haveibeenpwned.com/API/v2#PwnedPasswords
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()
    response_marker_to_search = password_hash[5:].upper()
    api_param = password_hash[:5]
    api_url = "https://api.pwnedpasswords.com/range/{}".format(api_param)
    api_headers = {'User-Agent': 'Pwnage-Checker-For-Devman'}
    try:
        with urllib.request.urlopen(
                urllib.request.Request(api_url, headers=api_headers)) as f:
            response = str(f.read())
    except urllib.error.URLError:
        response = ''

    return response.find(response_marker_to_search) > -1


def is_diverse(password):
    return len(Counter(password).keys()) > 6


def matched_by_banned_masks(password):
    filters = [
        # Dates
        '\d\d',
        '\d\d.\d\d'
        # Phones
        '\d\d-\d\d-\d\d',
        '\d{3}-\d{2,}',
        # licenses
        '[A-Z]{2}\d{3,}'
    ]
    return any(re.match(pattern, password) for pattern in filters)


def get_password_strength(password):
    strength = 1
    strength += has_normal_length(password)
    strength += has_perfect_length(password)
    strength += contains_number(password)
    strength += contains_lowercase_letters(password)
    strength += contains_uppercase_letters(password)
    strength += contains_non_alphanumeric(password)
    strength += not has_been_pwned(password)
    strength += is_diverse(password)
    strength += not matched_by_banned_masks(password)
    return strength


if __name__ == '__main__':
    password = getpass.getpass()
    strength = get_password_strength(password)
    print('Your password\'s score is {}'.format(strength))
