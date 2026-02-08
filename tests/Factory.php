<?php

namespace Ekapusta\OAuth2Esia\Tests;

use Bramus\Monolog\Formatter\ColoredLineFormatter;
use Bramus\Monolog\Formatter\ColorSchemes\TrafficLight;
use Ekapusta\OAuth2Esia\Jwt\JwtCompat;
use Ekapusta\OAuth2Esia\Provider\EsiaProvider;
use Ekapusta\OAuth2Esia\Security\JWTSigner\OpenSslCliJwtSigner;
use Ekapusta\OAuth2Esia\Token\EsiaAccessToken;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Monolog\Handler\NullHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Psr\Log\LoggerInterface;

class Factory
{
    const KEYS = EsiaProvider::RESOURCES;

    /**
     * @return LoggerInterface
     */
    public static function createLogger($channel = 'esia')
    {
        if (!in_array('--debug', $_SERVER['argv'])) {
            return new Logger($channel, [new NullHandler()]);
        }

        $logger = new Logger($channel);

        $formatter = new ColoredLineFormatter(new TrafficLight());
        $formatter->allowInlineLineBreaks();
        $formatter->ignoreEmptyContextAndExtra();

        $handler = (new StreamHandler('php://stderr'))->setFormatter($formatter);
        $logger->pushHandler($handler);

        return $logger;
    }

    /**
     * @return AuthenticationBot
     */
    public static function createAuthenticationBot()
    {
        $bot = new AuthenticationBot(
            'EsiaTest015@yandex.ru',
            '11111111',
            !getenv('DISPLAY'),
            'post' == getenv('ESIA_CLIENT_AUTH_METHOD')
        );
        $bot->setLogger(self::createLogger('authentication-bot'));

        return $bot;
    }

    /**
     * @return EsiaAccessToken
     */
    public static function createAccessToken($privateKeyPath, $publicKeyPath, Signer $signer)
    {
        $keyContent = file_get_contents($privateKeyPath);
        $key = JwtCompat::createKey($keyContent);

        if (JwtCompat::isV5()) {
            $token = self::buildTokenV5($signer, $key);
        } elseif (JwtCompat::isV4()) {
            $verificationKey = JwtCompat::createKey(file_get_contents($publicKeyPath));
            $token = self::buildTokenV4($signer, $key, $verificationKey);
        } else {
            $token = self::buildTokenV3($signer, $key);
        }

        $tokenString = method_exists($token, 'toString') ? $token->toString() : (string) $token;

        return new EsiaAccessToken(['access_token' => $tokenString], $publicKeyPath, $signer);
    }

    private static function buildTokenV3(Signer $signer, $key)
    {
        $builder = new \Lcobucci\JWT\Builder();
        $now = time();
        $hourLater = $now + 3600;
        $builder->setIssuedAt($now);
        $builder->setNotBefore($now);
        $builder->setExpiration($hourLater);
        $builder->set('urn:esia:sbj_id', 1);
        $builder->set('scope', 'one?oid=123 two?oid=456 three?oid=789 contacts?oid=999');

        return $builder->sign($signer, $key)->getToken();
    }

    /**
     * v4: Builder is an interface; get implementation from Configuration.
     */
    private static function buildTokenV4(Signer $signer, $signingKey, $verificationKey)
    {
        $config = \Lcobucci\JWT\Configuration::forAsymmetricSigner($signer, $signingKey, $verificationKey);
        $builder = $config->builder();
        $now = new \DateTimeImmutable();
        $hourLater = new \DateTimeImmutable('+1 hour');
        $builder->issuedAt($now);
        $builder->canOnlyBeUsedAfter($now);
        $builder->expiresAt($hourLater);
        $builder->withClaim('urn:esia:sbj_id', 1);
        $builder->withClaim('scope', 'one?oid=123 two?oid=456 three?oid=789 contacts?oid=999');

        return $builder->getToken($config->signer(), $config->signingKey());
    }

    private static function buildTokenV5(Signer $signer, $key)
    {
        $encoder = new \Lcobucci\JWT\Encoding\JoseEncoder();
        $formatter = \Lcobucci\JWT\Encoding\ChainedFormatter::default();
        $builder = \Lcobucci\JWT\Token\Builder::new($encoder, $formatter);
        $now = new \DateTimeImmutable();
        $hourLater = $now->modify('+1 hour');
        $builder = $builder->issuedAt($now)->canOnlyBeUsedAfter($now)->expiresAt($hourLater);
        $builder = $builder->withClaim('urn:esia:sbj_id', 1)->withClaim('scope', 'one?oid=123 two?oid=456 three?oid=789 contacts?oid=999');

        return $builder->getToken($signer, $key);
    }

    /**
     * @return EsiaAccessToken
     */
    public static function createSha256AccessToken($privateKeyPath, $publicKeyPath)
    {
        return self::createAccessToken($privateKeyPath, $publicKeyPath, new Sha256());
    }

    /**
     * @return EsiaAccessToken
     */
    public static function createGostAccessToken($privateKeyPath, $publicKeyPath)
    {
        return self::createAccessToken($privateKeyPath, $publicKeyPath, OpenSslCliJwtSigner::create(getenv('ESIA_CLIENT_OPENSSL_TOOL_PATH') ?: 'openssl'));
    }

    /**
     * @return EsiaAccessToken
     */
    public static function createRsaAccessToken($privateKeyPath, $publicKeyPath)
    {
        return self::createAccessToken($privateKeyPath, $publicKeyPath, OpenSslCliJwtSigner::create(getenv('ESIA_CLIENT_OPENSSL_TOOL_PATH') ?: 'openssl', 'RS256'));
    }
}
