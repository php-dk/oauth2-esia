<?php

namespace Ekapusta\OAuth2Esia\Jwt;

use Lcobucci\JWT\ValidationData;

/**
 * Wrapper for lcobucci/jwt v3.x and v4.x parsed token.
 */
final class ParsedTokenV34 implements ParsedTokenInterface
{
    private $token;

    public function __construct($token)
    {
        $this->token = $token;
    }

    /**
     * {@inheritdoc}
     */
    public function getClaim($name, $default = null)
    {
        if (method_exists($this->token, 'claims') && method_exists($this->token->claims(), 'get')) {
            return $this->token->claims()->get($name, $default);
        }

        return $this->token->getClaim($name, $default);
    }

    /**
     * {@inheritdoc}
     */
    public function validate()
    {
        $validationData = new ValidationData();

        return $this->token->validate($validationData);
    }

    /**
     * {@inheritdoc}
     */
    public function verify($signer, $key)
    {
        return $this->token->verify($signer, $key);
    }
}
