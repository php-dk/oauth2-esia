<?php

namespace Ekapusta\OAuth2Esia\Security\JWTSigner;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\CannotSignPayload;
use Lcobucci\JWT\Signer\Ecdsa\ConversionFailed;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key;

abstract class BaseSigner implements Signer
{
    public function sign(string $payload, Key $key): string
    {
        // TODO: Implement sign() method.
    }
}
