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
    return bool(re.search(r"\d", password))


def contains_lowercase_letters(password):
    return bool(re.search(r"[a-z]", password))


def contains_uppercase_letters(password):
    return bool(re.search(r"[A-Z]", password))


def contains_non_alphanumeric(password):
    return bool(re.search(r"[^a-zA-Z0-9]", password))


def get_pwnedpasswords_range(range):
    # https://haveibeenpwned.com/API/v2#PwnedPasswords
    api_url = "https://api.pwnedpasswords.com/range/{}".format(range)
    api_headers = {'User-Agent': 'Pwnage-Checker-For-Devman'}
    try:
        with urllib.request.urlopen(
                urllib.request.Request(api_url, headers=api_headers)) as pointer:
            return str(pointer.read())
    except urllib.error.URLError:
        return ''


def has_been_pwned(password):
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()
    response_marker_to_search = password_hash[5:].upper()
    range = password_hash[:5]

    return get_pwnedpasswords_range(range).find(response_marker_to_search) > -1


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
    return sum([
        1,
        has_normal_length(password),
        has_perfect_length(password),
        contains_number(password),
        contains_lowercase_letters(password),
        contains_uppercase_letters(password),
        contains_non_alphanumeric(password),
        not has_been_pwned(password),
        is_diverse(password),
        not matched_by_banned_masks(password)
    ])


if __name__ == '__main__':
    password = getpass.getpass()
    strength = get_password_strength(password)
    print("Your password's score is {}".format(strength))
