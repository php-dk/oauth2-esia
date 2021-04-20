<?php

namespace Ekapusta\OAuth2Esia\Token;

use Ekapusta\OAuth2Esia\Interfaces\Token\ScopedTokenInterface;
use InvalidArgumentException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Client\Token\AccessToken;

class EsiaAccessToken extends AccessToken implements ScopedTokenInterface
{
    private UnencryptedToken $parsedToken;
    private Configuration $config;

    public function __construct(array $options, Configuration $config)
    {
        parent::__construct($options);
        $this->config = $config;
        /** @var UnencryptedToken parsedToken */
        $this->parsedToken = $config->parser()->parse($this->accessToken);
        $this->resourceOwnerId = $this->parsedToken->claims()->get('urn:esia:sbj_id');
        if (! $this->config->validator()->validate($this->parsedToken, ...$this->config->validationConstraints())) {
            throw new InvalidArgumentException('Invalid token provided');
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
