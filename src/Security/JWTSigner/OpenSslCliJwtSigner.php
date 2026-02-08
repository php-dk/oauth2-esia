<?php

namespace Ekapusta\OAuth2Esia\Security\JWTSigner;

use Lcobucci\JWT\Signer\BaseSigner;

/**
 * JWT signer using OpenSSL CLI (GOST or RSA). Supports lcobucci/jwt v3, v4 and v5.
 *
 * Use create() to get an implementation for the installed JWT version:
 *   $signer = OpenSslCliJwtSigner::create('openssl', 'GOST3410_2012_256');
 *
 * On v3/v4 "new OpenSslCliJwtSignerV34()" can be used for the same behaviour as before.
 */
final class OpenSslCliJwtSigner
{
    /**
     * Returns a signer compatible with the installed lcobucci/jwt version (v3, v4 or v5).
     *
     * @param string $toolPath
     * @param string $algorythmId
     *
     * @return \Lcobucci\JWT\Signer|OpenSslCliJwtSignerV34
     */
    public static function create($toolPath = 'openssl', $algorythmId = 'GOST3410_2012_256')
    {
        if (class_exists(BaseSigner::class)) {
            return new OpenSslCliJwtSignerV34($toolPath, $algorythmId);
        }

        return new OpenSslCliJwtSignerV5($toolPath, $algorythmId);
    }
}
