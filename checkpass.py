import requests
import hashlib
import sys


def read_file(path):
    try:
        with open(path, mode='r') as file:
            lines = file.readlines()
            # rstrip() removes all whitespace characters(including new line and spaces)
            passwords = [line.rstrip() for line in lines]
            return passwords
    except FileNotFoundError as e:
        raise FileNotFoundError('Check the file path.') from e


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again!')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())

    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def check_pwned_api(password):
    if password == '' or password is None:
        raise AttributeError(f'Password cannot be null or empty, check the api an try again!')
    else:
        # check if password exists in API response
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        # the api needs only the fist 5 chars
        first5_char, tail = sha1_password[:5], sha1_password[5:]
        response = request_api_data(first5_char)
        return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = check_pwned_api(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password.')
        else:
            print(f'{password} was not found. Carry on!')
    return 'done!'


if __name__ == '__main__':
    # sending passwords using command line args (security risk as the password are saved in the command line)
    # sys.exit(main(sys.argv[1:]))
    # sending passwords using a txt file (password.txt)
    sys.exit(main(read_file('passwords.txt')))
