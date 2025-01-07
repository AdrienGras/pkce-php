<?php

namespace AdrienGras\PKCE;

use Exception;

/**
 * Class PKCEUtils
 * @package AdrienGras\PKCE
 * @see https://tools.ietf.org/html/rfc7636
 */
class PKCEUtils
{
    /**
     * @var string Code challenge validation: plain-text.
     * <b>Warning</b>: This method is <b>for testing purpose only</b> and should not be used in production.
     * @see https://tools.ietf.org/html/rfc7636#section-4.2
     */
    public const CODE_CHALLENGE_METHOD_PLAIN = 'plain';

    /**
     * @var string Code challenge validation: S256 (SHA-256).
     * @see https://tools.ietf.org/html/rfc7636#section-4.2
     */
    public const CODE_CHALLENGE_METHOD_S256 = 'S256';

    // 66 characters, differs from the urlsafe base64 charset               
    private const PKCE_VERIFIER_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';


    /**
     * Generate a code verifier given a length. (default: 64)
     * @param int $length The length of the code verifier. It must be between 43 and 128.
     * @return string The code verifier.
     * @throws Exception if an appropriate source of randomness cannot be found.
     * @see https://tools.ietf.org/html/rfc7636#section-4.1
     * @see https://github.com/AdrienGras/pkce-php/issues/8
     */
    public static function generateCodeVerifier(int $length = 64): string
    {
        $str = "";

        if ($length < 43 || $length > 128) {
            throw new \InvalidArgumentException('The length of the code verifier must be between 43 and 128. See https://tools.ietf.org/html/rfc7636#section-4.1');
        }

        for ($i = 0; $i < $length; $i++) {
            $str .= self::PKCE_VERIFIER_CHARSET[random_int(0, strlen(self::PKCE_VERIFIER_CHARSET) - 1)];
        }

        return $str;
    }

    /**
     * Derive a code challenge from a code verifier.
     * @param string $codeVerifier The code verifier to derive a code challenge from.
     * @param string $codeChallengeMethod The code challenge method to use. Use one of the constants from this class.
     * @return string The code challenge.
     * @see https://github.com/AdrienGras/pkce-php/issues/8
     */
    public static function generateCodeChallenge(
        string $codeVerifier,
        string $codeChallengeMethod = self::CODE_CHALLENGE_METHOD_S256
    ): string {
        if (false === in_array($codeChallengeMethod, self::supportedCodeChallengeMethods())) {
            throw new \InvalidArgumentException(sprintf('Code challenge method "%s" is not supported.', $codeChallengeMethod));
        }

        if (self::CODE_CHALLENGE_METHOD_PLAIN === $codeChallengeMethod) {
            // quick exit, since there is no transformation
            return $codeVerifier;
        }

        $hash = hash('sha256', $codeVerifier, true);
        return sodium_bin2base64($hash, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * Generate a code verifier and a code challenge.
     * @return array The code verifier and the code challenge.
     * @throws Exception if an appropriate source of randomness cannot be found.
     */
    public static function generateCodePair(string $codeChallengeMethod = self::CODE_CHALLENGE_METHOD_S256): array
    {
        $verifier = self::generateCodeVerifier();

        return [
            'code_verifier' => $verifier,
            'code_challenge' => self::generateCodeChallenge($verifier, $codeChallengeMethod),
        ];
    }

    /**
     * Verify a code challenge against a code verifier.
     * @param string $codeVerifier The code verifier.
     * @param string $codeChallenge The code challenge.
     * @param string $codeChallengeMethod The code challenge method to use. Use one of the constants from this class.
     * @return bool Whether the code challenge is valid.
     */
    public static function validate(
        string $codeVerifier,
        string $codeChallenge,
        string $codeChallengeMethod = self::CODE_CHALLENGE_METHOD_S256
    ): bool {
        return hash_equals($codeChallenge, self::generateCodeChallenge($codeVerifier, $codeChallengeMethod));
    }

    /**
     * Get the supported code challenge methods.
     * @return string[] The supported code challenge methods.
     */
    public static function supportedCodeChallengeMethods(): array
    {
        return [
            self::CODE_CHALLENGE_METHOD_PLAIN,
            self::CODE_CHALLENGE_METHOD_S256,
        ];
    }
}
