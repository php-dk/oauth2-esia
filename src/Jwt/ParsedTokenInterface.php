<?php

namespace Ekapusta\OAuth2Esia\Jwt;

interface ParsedTokenInterface
{
    /**
     * @param string $name
     * @param mixed  $default
     *
     * @return mixed
     */
    public function getClaim($name, $default = null);

    /**
     * @return bool
     */
    public function validate();

    /**
     * @param object $signer lcobucci/jwt Signer (v3/v4 or v5)
     * @param object $key    lcobucci/jwt Key
     *
     * @return bool
     */
    public function verify($signer, $key);
}
