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

    /**
     * Generate a code verifier.
     * @see https://tools.ietf.org/html/rfc7636#section-4.1
     * @return string The code verifier.
     * @throws Exception if an appropriate source of randomness cannot be found.
     */
    public static function generateCodeVerifier(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(64)), '+/', '-_'), '=');
    }

    /**
     * Derive a code challenge from a code verifier.
     * @param string $codeVerifier The code verifier to derive a code challenge from.
     * @param string $codeChallengeMethod The code challenge method to use. Use one of the constants from this class.
     * @return string The code challenge.
     */
    public static function generateCodeChallenge(
        string $codeVerifier,
        string $codeChallengeMethod = self::CODE_CHALLENGE_METHOD_S256
    ): string
    {
        if (false === in_array($codeChallengeMethod, self::supportedCodeChallengeMethods())) {
            throw new \InvalidArgumentException(sprintf('Code challenge method "%s" is not supported.', $codeChallengeMethod));
        }

        if (self::CODE_CHALLENGE_METHOD_PLAIN === $codeChallengeMethod) {
            return $codeVerifier;
        }

        if (self::CODE_CHALLENGE_METHOD_S256 === $codeChallengeMethod) {
            $codeChallengeMethod = 'sha256';
        }

        return rtrim(strtr(base64_encode(hash($codeChallengeMethod, $codeVerifier, true)), '+/', '-_'), '=');
    }

    /**
     * Generate a code verifier and a code challenge.
     * @return array The code verifier and the code challenge.
     * @throws Exception if an appropriate source of randomness cannot be found.
     */
    public static function generateCodePair(string $codeChallengeMethod = self::CODE_CHALLENGE_METHOD_S256): array {
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
    ): bool
    {
        return $codeChallenge === self::generateCodeChallenge($codeVerifier, $codeChallengeMethod);
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