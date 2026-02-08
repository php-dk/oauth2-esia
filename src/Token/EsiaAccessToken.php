<?php

namespace Ekapusta\OAuth2Esia\Token;

use Ekapusta\OAuth2Esia\Jwt\JwtCompat;
use InvalidArgumentException;
use Lcobucci\JWT\Signer;

class EsiaAccessToken extends TrustedEsiaAccessToken
{
    public function __construct(array $options, $publicKeyPath, Signer $signer)
    {
        parent::__construct($options);

        $key = JwtCompat::createKey(file_get_contents($publicKeyPath));
        if (!$this->parsedToken->verify($signer, $key)) {
            throw new InvalidArgumentException('Access token can not be verified: '.var_export($options, true));
        }
    }
}
