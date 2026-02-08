<?php

namespace Ekapusta\OAuth2Esia\Jwt;

use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Validator;

/**
 * Wrapper for lcobucci/jwt v5.x parsed token.
 */
final class ParsedTokenV5 implements ParsedTokenInterface
{
    private $token;

    private static $validator;

    public function __construct($token)
    {
        $this->token = $token;
    }

    /**
     * {@inheritdoc}
     */
    public function getClaim($name, $default = null)
    {
        return $this->token->claims()->get($name, $default);
    }

    /**
     * {@inheritdoc}
     */
    public function validate()
    {
        $constraints = $this->getTimeValidationConstraints();
        if (empty($constraints)) {
            return true;
        }

        return $this->getValidator()->validate($this->token, ...$constraints);
    }

    /**
     * {@inheritdoc}
     */
    public function verify($signer, $key)
    {
        return $this->getValidator()->validate(
            $this->token,
            new SignedWith($signer, $key)
        );
    }

    private static function getValidator()
    {
        if (self::$validator === null) {
            self::$validator = new Validator();
        }

        return self::$validator;
    }

    /**
     * StrictValidAt requires lcobucci/clock. Without it we skip time validation in v5.
     *
     * @return array
     */
    private function getTimeValidationConstraints()
    {
        if (class_exists(\Lcobucci\Clock\SystemClock::class)) {
            return [new StrictValidAt(\Lcobucci\Clock\SystemClock::fromUTC())];
        }

        if (class_exists(\Lcobucci\Clock\FrozenClock::class)) {
            return [new StrictValidAt(new \Lcobucci\Clock\FrozenClock(new \DateTimeImmutable()))];
        }

        return [];
    }
}
