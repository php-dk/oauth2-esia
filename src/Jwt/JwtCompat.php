<?php

namespace Ekapusta\OAuth2Esia\Jwt;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser as TokenParser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Validator;

/**
 * Compatibility layer for lcobucci/jwt ^3.2.2 || ^4.0 || ^5.0.
 */
final class JwtCompat
{
    private static $encoder;

    /**
     * Parse JWT string and return unified ParsedTokenInterface.
     *
     * @param string $jwt
     *
     * @return ParsedTokenInterface
     */
    public static function parse($jwt)
    {
        if (self::isV5()) {
            $parser = new TokenParser(new JoseEncoder());
            $token = $parser->parse($jwt);

            return new ParsedTokenV5($token);
        }

        if (self::isV4()) {
            $parser = self::createV4Parser();
            $token = $parser->parse($jwt);

            return new ParsedTokenV34($token);
        }

        $parser = new \Lcobucci\JWT\Parser();
        $token = $parser->parse($jwt);

        return new ParsedTokenV34($token);
    }

    /**
     * Create Key instance from raw content (file contents or string).
     *
     * @param string $content
     *
     * @return object lcobucci/jwt Key
     */
    public static function createKey($content)
    {
        if (self::isV5() || self::isV4()) {
            return \Lcobucci\JWT\Signer\Key\InMemory::plainText($content);
        }

        return new \Lcobucci\JWT\Signer\Key($content);
    }

    /**
     * Base64Url-encode data (for client_secret and similar).
     *
     * @param string $data
     *
     * @return string
     */
    public static function base64UrlEncode($data)
    {
        if (self::$encoder === null) {
            self::$encoder = self::createEncoder();
        }

        if (method_exists(self::$encoder, 'base64UrlEncode')) {
            return self::$encoder->base64UrlEncode($data);
        }
        // Fallback for encoders that only have encode() or different API
        return strtr(rtrim(base64_encode($data), '='), '+/', '-_');
    }

    /**
     * v4 also has Token\Parser, JoseEncoder, Validator. v5 is detected by Token\Builder::new().
     */
    public static function isV5()
    {
        return class_exists(\Lcobucci\JWT\Token\Builder::class)
            && method_exists(\Lcobucci\JWT\Token\Builder::class, 'new');
    }

    public static function isV4()
    {
        return class_exists(\Lcobucci\JWT\Configuration::class)
            && !self::isV5();
    }

    private static function createEncoder()
    {
        if (class_exists(JoseEncoder::class)) {
            return new JoseEncoder();
        }
        if (class_exists(\Lcobucci\JWT\Parsing\Encoder::class)) {
            return new \Lcobucci\JWT\Parsing\Encoder();
        }

        throw new \RuntimeException('No JWT encoder found (lcobucci/jwt Parsing\\Encoder or Encoding\\JoseEncoder)');
    }

    /**
     * In v4 Parser is an interface; get implementation from Configuration.
     */
    private static function createV4Parser()
    {
        $config = \Lcobucci\JWT\Configuration::forUnsecuredSigner();

        return $config->parser();
    }
}
