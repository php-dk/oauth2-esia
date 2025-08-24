<?php

namespace Ekapusta\OAuth2Esia\Token;

use Ekapusta\OAuth2Esia\Interfaces\Token\ScopedTokenInterface;
use InvalidArgumentException;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use League\OAuth2\Client\Token\AccessToken;

class EsiaAccessToken extends AccessToken implements ScopedTokenInterface
{
    private UnencryptedToken $parsedToken;
    private Configuration $config;

    public function __construct(array $options, Configuration $config)
    {
        parent::__construct($options);
        $this->config = $config;
        $clock = SystemClock::fromUTC();
        $config->setValidationConstraints(
            new LooseValidAt($clock),
            new StrictValidAt($clock),
        );

        /** @var UnencryptedToken parsedToken */
        $this->parsedToken = $config->parser()->parse($this->accessToken);
        $this->resourceOwnerId = $this->parsedToken->claims()->get('urn:esia:sbj_id');
        if (! $this->config->validator()->validate($this->parsedToken, ...$this->config->validationConstraints())) {
            throw new InvalidArgumentException('Access token is invalid: '.var_export($options, true));
        }
    }

    public function getScopes(): array
    {
        $scopes = [];
        $token = $this->parsedToken;
        foreach (explode(' ', $token->claims()->get('scope', '')) as $scope) {
            $scopes[] = parse_url($scope, PHP_URL_PATH);
        }

        return $scopes;
    }
}
