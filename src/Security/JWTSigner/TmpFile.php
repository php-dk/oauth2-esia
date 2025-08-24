<?php

namespace Ekapusta\OAuth2Esia\Security\JWTSigner;

final class TmpFile
{
    private $path;

    public function __construct($content)
    {
        $handler = tmpfile();
        fwrite($handler, $content);
        fseek($handler, 0);

        $this->path = stream_get_meta_data($handler)['uri'];
    }

    public function __toString()
    {
        return $this->path;
    }
}
