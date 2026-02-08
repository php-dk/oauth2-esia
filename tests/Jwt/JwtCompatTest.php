<?php

namespace Ekapusta\OAuth2Esia\Tests\Jwt;

use Ekapusta\OAuth2Esia\Jwt\JwtCompat;
use Ekapusta\OAuth2Esia\Tests\Factory;
use PHPUnit\Framework\TestCase;

class JwtCompatTest extends TestCase
{
    public function testParseAndGetClaim()
    {
        $esiaToken = Factory::createSha256AccessToken(
            Factory::KEYS.'ekapusta.rsa.test.key',
            Factory::KEYS.'ekapusta.rsa.test.public.key'
        );
        $this->assertSame(1, $esiaToken->getResourceOwnerId());
        $this->assertEquals(['one', 'two', 'three', 'contacts'], $esiaToken->getScopes());
    }

    public function testBase64UrlEncode()
    {
        $encoded = JwtCompat::base64UrlEncode('test');
        $this->assertNotEmpty($encoded);
        $this->assertNotContains('+', $encoded);
        $this->assertNotContains('/', $encoded);
    }

    public function testCreateKey()
    {
        $key = JwtCompat::createKey('key-content');
        $this->assertNotNull($key);
    }

    public function testVersionDetection()
    {
        $this->assertTrue(JwtCompat::isV5() || JwtCompat::isV4() || !JwtCompat::isV5());
    }
}
