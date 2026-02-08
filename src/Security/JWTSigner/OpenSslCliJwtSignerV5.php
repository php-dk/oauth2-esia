<?php

namespace Ekapusta\OAuth2Esia\Security\JWTSigner;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

/**
 * lcobucci/jwt v5.x signer (implements Signer interface with sign/verify).
 */
final class OpenSslCliJwtSignerV5 implements Signer
{
    use OpenSslCliJwtSignerLogic;

    public function __construct($toolPath = 'openssl', $algorythmId = 'GOST3410_2012_256')
    {
        $this->initOpenSslCliJwtSigner($toolPath, $algorythmId);
    }

    public function algorithmId(): string
    {
        return $this->algorythmId;
    }

    public function sign(string $payload, Key $key): string
    {
        return $this->createHashString($payload, $this->getKeyContent($key));
    }

    public function verify(string $expected, string $payload, Key $key): bool
    {
        try {
            $this->doVerifyString($expected, $payload, $this->getKeyContent($key));

            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }
}
