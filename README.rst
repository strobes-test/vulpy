Vulpy - Web Application Security Labs
====================================

Vulpy is a web application developed in Python / Flask / SQLite that has two faces.

**GOOD**: Tries to code with secure development best practices in mind.

**BAD**: Tries to code like (possibly) you. :p


OWASP Application Security Verification Standard
------------------------------------------------

The "GOOD" version (not finished yet) will comply with the OWASP ASVS:

https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project

This will permit learn how to develop python code following the best security practices.


Installation
------------

::

   git clone https://github.com/portantier/vulpy

   cd vulpy

   pip3 install --user -r requirements.txt
   pip3 install -e .


Features
--------

- Login/Logout
- Read posts from other users
- Publish posts
- Multi-Factor Authentication (MFA)
- API for read and write posts
- Content Security Policy
- SSL/TLS Server


Vulnerabilities
---------------

Some of the vulnerabilities present on the "BAD" version:

- Cross-Site Scripting (XSS)
- SQL Injection
- Cross Site Request Forgery (CSRF)
- Session Impersonation
- Authentication Bruteforce
- Authentication Bypass

**Note:** The "GOOD" version (not finished yet) is supposed to don't have vulnerabilities, but I'm a human being, so...


Database Initialization
-----------------------

Both, "BAD" and "GOOD" versions, requires an initialization of the database.

This is done with the script "db_init.py" inside each of the directories (bad, and good).

Each version has their own sqlite files for the users and posts.

The execution of the script is, for example:

::

   cd bad
   ./db_init.py


Default Credentials
-------------------

After database initialization, three users are created:

::

   Username    Password
   --------    -----------
   admin       SuperSecret
   elliot      123123123
   tim         12345678


You can login with any user, the application doesn't have a permissions system, so, the three have the same permissions.

asdsfd



export AWS_ACCESS_KEY_ID="ASIAXAO5AVIJHMGZVKQQ"
export AWS_SECRET_ACCESS_KEY="nZX9fEbpidya9SxHfAKCnGUrhm+KxqDUCMOuCyRR"
