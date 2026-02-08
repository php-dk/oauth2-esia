<?php

namespace Ekapusta\OAuth2Esia\Security\JWTSigner;

use Lcobucci\JWT\Signer\BaseSigner;
use Lcobucci\JWT\Signer\Key;

/**
 * lcobucci/jwt v3.x and v4.x signer (extends BaseSigner).
 */
final class OpenSslCliJwtSignerV34 extends BaseSigner
{
    use OpenSslCliJwtSignerLogic;

    public function __construct($toolPath = 'openssl', $algorythmId = 'GOST3410_2012_256')
    {
        $this->initOpenSslCliJwtSigner($toolPath, $algorythmId);
    }

    public function getAlgorithmId()
    {
        return $this->algorythmId;
    }

    public function doVerify($expected, $payload, Key $key)
    {
        return $this->doVerifyString($expected, $payload, $this->getKeyContent($key));
    }

    public function createHash($payload, Key $key)
    {
        return $this->createHashString($payload, $this->getKeyContent($key));
    }
}
