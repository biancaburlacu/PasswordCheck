import hashlib
import unittest

from checkpass import read_file, request_api_data, get_password_leaks_count, check_pwned_api


class CheckPassTest(unittest.TestCase):

    def test_read_file_correct_path(self):
        path = 'passwords.txt'
        with open(path, 'w') as file:
            file.write("password1\njasdh1234\ntest12\n")
        result = read_file(path)
        expected_passwords = ['password1', 'jasdh1234', 'test12']
        self.assertEqual(result, expected_passwords)

    def test_read_file_empty(self):
        path = 'empty.txt'
        with open(path, 'w') as file:
            file.write("")
        result = read_file(path)
        self.assertTrue(len(result) == 0)

    def test_read_file_invalid_path(self):
        with self.assertRaises(FileNotFoundError) as err:
            read_file("non_existing_file.txt")
        self.assertTrue("Check the file path." in str(err.exception))

    def test_request_api_data_hashed(self):
        hash_code = '8B673'
        expected_code = 200
        actual = request_api_data(hash_code)
        self.assertEqual(actual.status_code, expected_code)

    def test_request_api_data_wrong_input(self):
        input_data = 'abc'
        with self.assertRaises(RuntimeError) as err:
            request_api_data(input_data)

    def test_get_password_leaks_count_weak_pass(self):
        pass_to_check = 'hello'
        sha1_password = hashlib.sha1(pass_to_check.encode('utf-8')).hexdigest().upper()
        first5_char, tail = sha1_password[:5], sha1_password[5:]
        response = request_api_data(first5_char)
        count = int(get_password_leaks_count(response, tail))
        self.assertTrue(count > 0)

    def test_get_password_leaks_count_strong_pass(self):
        pass_to_check = '612*&&%%BC012?#'
        sha1_password = hashlib.sha1(pass_to_check.encode('utf-8')).hexdigest().upper()
        first5_char, tail = sha1_password[:5], sha1_password[5:]
        response = request_api_data(first5_char)
        count = int(get_password_leaks_count(response, tail))
        self.assertTrue(count == 0)

    def test_check_pwned_api_weak_pass(self):
        pass_to_check = 'test123'
        count = int(check_pwned_api(pass_to_check))
        self.assertTrue(count > 0)

    def test_check_pwned_api_strong_pass(self):
        pass_to_check = '&%&12(^t3$T)'
        count = int(check_pwned_api(pass_to_check))
        self.assertEqual(count, 0)

    def test_check_pwned_api_empty_pass(self):
        with self.assertRaises(AttributeError) as err:
            check_pwned_api('')

    def test_check_pwned_api_None_pass(self):
        with self.assertRaises(AttributeError) as err:
            check_pwned_api(None)


if __name__ == '__main__':
    unittest.main()
