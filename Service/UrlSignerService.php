<?php

declare(strict_types=1);

namespace Jmoati\UrlSignerBundle\Service;

use Symfony\Component\HttpFoundation\Request;

class UrlSignerService
{
    const FIVE_MINUTES = 300;

    /**
     * @param string $httpMethod
     * @param string $url
     * @param string $key
     * @param int    $expires
     *
     * @return string
     */
    public function signUrl(string $httpMethod, string $url, string $key, int $expires = null): string
    {
        if (null === $expires) {
            $expires = time() + self::FIVE_MINUTES;
        }

        $url .= sprintf('?expires=%d', $expires);
        $signature = base64_encode(hash_hmac('sha256', sprintf('%s|%s', $httpMethod, $url), $key, true));

        return sprintf('%s&signature=%s', $url, rawurlencode($signature));
    }

    /**
     * @param Request $request
     * @param string  $key
     *
     * @return bool
     */
    public function checkUrl(Request $request, string $key)
    {
        $expires = $request->query->getInt('expires');
        $signature = $request->query->get('signature');

        if (null === $signature || $expires < time()) {
            return false;
        }

        $method = $request->getMethod();
        $url = $request->getPathInfo();
        $signature = rawurlencode($signature);

        $signedUrl = $this->signUrl($method, $url, $key, $expires);
        $queriedUrl = sprintf('%s?expires=%d&signature=%s', $url, $expires, $signature);

        return $signedUrl === $queriedUrl;
    }
}
