<?php

namespace AdrienGras\PKCE\Tests;

use AdrienGras\PKCE\PKCEUtils;
use PHPUnit\Framework\TestCase;

class TestSuite extends TestCase
{

    public function testGenerateCodeVerifier()
    {
        $this->assertIsString(PKCEUtils::generateCodeVerifier());
    }

    public function testGenerateCodeChallengePlain()
    {
        $codeVerifier = "M1saaz2h5oXNXb5pMwq600B2-oAjnWO1-J2Z2ZQD_Gw";
        $possibleCodeChallenge= "M1saaz2h5oXNXb5pMwq600B2-oAjnWO1-J2Z2ZQD_Gw";
        $codeChallengeMethod = PKCEUtils::CODE_CHALLENGE_METHOD_PLAIN;

        $generatedCodeChallenge = PKCEUtils::generateCodeChallenge($codeVerifier, $codeChallengeMethod);

        $this->assertSame($possibleCodeChallenge, $generatedCodeChallenge);
    }

    public function testGenerateCodeChallengeSHA256()
    {
        $codeVerifier = "lvE_-45Afo2f6hz50KvvxvQH5WK1sBSRpcEy6Hyxvrc";
        $possibleCodeChallenge = "6DHGaA1z71MZa6BGV2tS4OO-317gZfSWJGq9LYJj-8k";
        $codeChallengeMethod = PKCEUtils::CODE_CHALLENGE_METHOD_S256;

        $generatedCodeChallenge = PKCEUtils::generateCodeChallenge($codeVerifier, $codeChallengeMethod);

        $this->assertSame($possibleCodeChallenge, $generatedCodeChallenge);
    }

    public function testValidation()
    {
        $codeVerifier = "lvE_-45Afo2f6hz50KvvxvQH5WK1sBSRpcEy6Hyxvrc";
        $possibleCodeChallenge = "6DHGaA1z71MZa6BGV2tS4OO-317gZfSWJGq9LYJj-8k";
        $codeChallengeMethod = PKCEUtils::CODE_CHALLENGE_METHOD_S256;

        $this->assertTrue(PKCEUtils::validate($codeVerifier, $possibleCodeChallenge, $codeChallengeMethod));
    }

    public function testGenerateKeyPair()
    {
        $keyPair = PKCEUtils::generateKeyPair();

        $this->assertIsArray($keyPair);
        $this->assertArrayHasKey('code_verifier', $keyPair);
        $this->assertArrayHasKey('code_challenge', $keyPair);
        $this->assertIsString($keyPair['code_verifier']);
        $this->assertIsString($keyPair['code_challenge']);
    }

    public function testSupportedCodeChallengeMethods()
    {
        $supported = PKCEUtils::supportedCodeChallengeMethods();
        $this->assertIsArray($supported);
        $this->assertContains(PKCEUtils::CODE_CHALLENGE_METHOD_PLAIN, $supported);
        $this->assertContains(PKCEUtils::CODE_CHALLENGE_METHOD_S256, $supported);
    }

}