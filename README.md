# pkce-php

![GitHub](https://img.shields.io/github/license/AdrienGras/pkce-php)
![GitHub workflows](https://github.com/AdrienGras/pkce-php/actions/workflows/php.yml/badge.svg)

A simple utility to use PKCE (Proof Key for Code Exchange) in PHP.

This little utility is intended to help people using Oauth2 with PKCE in PHP. It provides a simple way to generate a code verifier, a code challenge and to validate a code verifier with a code challenge.

## Summary

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Features

- [x] Generate a code verifier
- [x] Generate a code challenge from a given code verifier
- [x] Generate a pair of code verifier and code challenge
- [x] Verify a code verifier with a code challenge

> **Note:** All the code complies to the [RFC 7636](https://tools.ietf.org/html/rfc7636).

## Installation

Using composer:

```bash
composer require adriengras/pkce-php
```

## Usage

```php
// import with composer autoloader
use AdrienGras\PKCE\PKCE;

// ...

// generate a code verifier
$verifier = PKCEUtils::generateCodeVerifier();

// generate a code challenge from the code verifier
$challenge = PKCEUtils::generateCodeChallenge($verifier);

// you can also use the plain text challenge method for testing purpose
// WARNING: this method is not secure and should not be used in production
$challenge = PKCEUtils::generateCodeChallenge($verifier, PKCEUtils::CODE_CHALLENGE_METHOD_PLAIN);

// alternatively, generate a pair of code verifier and code challenge
$pair = PKCEUtils::generateCodePair();
$verifier = $pair['code_verifier'];
$challenge = $pair['code_challenge'];
// or with destructuring
['code_verifier' => $verifier, 'code_challenge' => $challenge] = PKCEUtils::generateCodePair();

// validate a code verifier with a code challenge
$isValid = PKCEUtils::validate($verifier, $challenge);
```

> **Note** You can also use the test case suite as a full example on how to use this utility. You can find it in the [tests](tests) folder.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
