# Project 6 - Globitek Authentication and Login Throttling

Time spent: **6** hours spent in total

## User Stories

The following **required** functionality is completed:

1\. "staff/users/new.php" and "staff/users/edit.php"
  * [x]  Form with inputs for "Password" and "Confirm Password"
  * [x]  Strong password requirements text

2\. Data validations
  * [x]  Returns an error if password or confirm_password are blank.
  * [x]  Returns an error if password and confirm_password do not match.
  * [x]  Returns an error if password is not at least 12 characters long.
  * [x]  Returns an error if password does not meet character requirements.
  * [x]  Returns any errors related to other validations already on the user.

3\. Saving a user
  * [x]  Encrypts the password
  * [x]  Stores the password in the database

4\. Login page
  * [x]  Verify the correct password.
  * [x]  Do not create a User Enumeration vulnerability.

5\. If a user fails to log in:
  * [x]  Record the failed login for the first 5 attempts.
  * [x]  Return a "too many failed logins" message after 5 attempts.
  * [x]  Future attempts will show the number of minutes remaining in the lockout.
  * [x]  After the lockout period, the failed logins count resets to 0.

6\. After any successful login:
  * [x]  Set the failed_logins.count for the username to 0.

7\. SQLi and XSS
  * [x]  Do not introduce any SQLI Injection and Cross-Site Scripting vulnerabilities.

The following advanced user stories are optional:

* Bonus Objective 1\.
  * [x]  Identify the subtle Username Enumeration weakness. Include a short description of how the code could be modified to be more secure below:
    * One of bcrypt's strengths is its slowness that serves as a bottleneck to brute force/dictionary attacks. However, since bcrypt hashing only happens if the username already exists, the hacker may notice it's taking more time for the page to reload for a user that exists, especially if a long password is passed in, than being instantaneously redirected to the errors when logging in as a user that doesn't exist.

* Bonus Objective 2\.
  * [x]  User password validations only run when the password is not blank.
  * [x]  `update_user` only encrypts and updates the password when the password is not blank.

* Bonus Objective 3\.
  * [x]  Create a new user using cost 10.
  * [x]  Set bcrypt "cost" parameter to 11 (for both insert and update).
  * [x]  Try to login with the "cost 10" user.
  * [x]  Briefly describe why login still works even after the cost is changed:
    * The password_hash function returns a hashed string that contains the algorithm, cost and salt of hashing, so all information needed to verify the hash by the password_verify function is present. Thus, it will verify password using whatever cost was used in hashing.

* Bonus Objective 4\.
  * [x]  Add "Previous password" to "public/staff/users/edit.php"
  * [x]  Validate the previous password before allowing the password to be updated.
  * [x]  Require previous password only if new password is being updated (if also completing Bonus Objective 2).

* Advanced Objective 1\.
  * [x]  Implement `password_hash()` on your own as `my_password_hash()`.
  * [x]  Implement `password_verify()` on your own as `my_password_verify()`.

* Advanced Objective 2\.
  * [x]  Write `generate_strong_password()`
  * [x]  Add a suggestion for a 12-character strong password to the new and edit user pages.

## Video Walkthrough

Here's a walkthrough of implemented user stories:

<img src='/globitek.gif?raw=truef' title='Video Walkthrough' width='' alt='Video Walkthrough' />

GIF created with [LiceCap](http://www.cockos.com/licecap/).

## Notes

Describe any challenges encountered while building the app.

## License

    Copyright [2017] [Thant Htoo Zaw]

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
