<?php

namespace Ekapusta\OAuth2Esia\Security\JWTSigner;

use Ekapusta\OAuth2Esia\Transport\Process;

/**
 * Shared logic for OpenSSL CLI JWT signer (v3/v4 and v5).
 */
trait OpenSslCliJwtSignerLogic
{
    private $toolPath;
    private $algorythmId;
    private $postParams = '';

    protected function initOpenSslCliJwtSigner($toolPath = 'openssl', $algorythmId = 'GOST3410_2012_256')
    {
        $this->toolPath = $toolPath;
        $this->algorythmId = $algorythmId;

        if (false !== stristr($this->algorythmId, 'gost')) {
            $this->postParams = '-engine gost';
        }
    }

    protected function doVerifyString($expected, $payload, $keyContent)
    {
        $verify = new TmpFile($keyContent);
        $signature = new TmpFile($expected);

        Process::fromArray([
            $this->toolPath,
            'dgst',
            '-verify '.escapeshellarg($verify),
            '-signature '.escapeshellarg($signature),
            $this->postParams,
        ], $payload);

        return true;
    }

    protected function createHashString($payload, $keyContent)
    {
        $sign = new TmpFile($keyContent);

        return (string) Process::fromArray([
            $this->toolPath,
            'dgst',
            '-sign '.escapeshellarg($sign),
            $this->postParams,
        ], $payload);
    }

    protected function getKeyContent($key)
    {
        if (method_exists($key, 'contents')) {
            return $key->contents();
        }

        return method_exists($key, 'get') ? $key->get() : $key->getContent();
    }
}
