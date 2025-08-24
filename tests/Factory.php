<?php

namespace Ekapusta\OAuth2Esia\Tests;

use Bramus\Monolog\Formatter\ColoredLineFormatter;
use Bramus\Monolog\Formatter\ColorSchemes\TrafficLight;
use DateTimeImmutable;
use Ekapusta\OAuth2Esia\Provider\EsiaProvider;
use Ekapusta\OAuth2Esia\Security\JWTSigner\OpenSslCliJwtSigner;
use Ekapusta\OAuth2Esia\Token\EsiaAccessToken;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Monolog\Handler\NullHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Psr\Log\LoggerInterface;
use Lcobucci\JWT\Configuration;

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
            'EsiaTest006@yandex.ru',
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
    public static function createAccessToken($privateKeyPath, $publicKeyPath, Signer $signer = null)
    {
        if (null == $signer) {
            $config = Configuration::forAsymmetricSigner(new Sha256(), Key\InMemory::file($publicKeyPath), Key\InMemory::file($privateKeyPath));
        } else {
            $config = Configuration::forUnsecuredSigner();
        }

        $accessToken = $config->builder()
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt(new DateTimeImmutable('+1 hour'))
            ->withHeader('urn:esia:sbj_id', 1)
            ->withClaim('scope', 'one?oid=123 two?oid=456 three?oid=789')
            ->getToken($config->signer(), $config->signingKey());

        return new EsiaAccessToken(['access_token' => $accessToken->toString()], $config);
    }

    /**
     * @return EsiaAccessToken
     */
    public static function createGostAccessToken($privateKeyPath, $publicKeyPath)
    {
        return self::createAccessToken($privateKeyPath, $publicKeyPath, new OpenSslCliJwtSigner(getenv('ESIA_CLIENT_OPENSSL_TOOL_PATH') ?: 'openssl'));
    }

    /**
     * @return EsiaAccessToken
     */
    public static function createRsaAccessToken($privateKeyPath, $publicKeyPath)
    {
        return self::createAccessToken($privateKeyPath, $publicKeyPath, new OpenSslCliJwtSigner(getenv('ESIA_CLIENT_OPENSSL_TOOL_PATH') ?: 'openssl', 'RS256'));
    }
}
