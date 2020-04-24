<?php

namespace SHS\DoEIdP;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

class IdPDriver 
{
    const URL_BASE     = 'https://sso.det.nsw.edu.au/sso/json/realms/root/';

    const URL_AUTH     = 'authenticate?goto=https://portal.det.nsw.edu.au';
    const URL_VALIDATE = 'sessions?_action=validate';

    /** @var ClientInterface */
    protected $client;

    /** @var RequestFactoryInterface */
    protected $requestFactory;

    /** @var StreamFactoryInterface */
    protected $streamFactory;

    /** @var string */
    protected $base;

    public function __construct(ClientInterface $client, RequestFactoryInterface $requestFactory, StreamFactoryInterface $streamFactory, ?string $idPBase = null)
    {
        $this->client = $client;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;

        $this->base = $idPBase ?? static::URL_BASE;
    }

    public function login($username, $password): ResponseInterface
    {  
        // 1 - POST blank to get the auth template
        $request = $this->requestFactory->createRequest('POST', $this->base.static::URL_AUTH);
        $response = $this->client->sendRequest($request);

        // json
        $authBody = json_decode($response->getBody()->getContents());
        $authCookie = $this->getLoginSessionCookies($response);

        foreach ($authBody->callbacks as $cb) {
            if ($cb->type == 'NameCallback') {
                $cb->input[0]->value = $username;
            }
            if ($cb->type == 'PasswordCallback') {
                $cb->input[0]->value = $password;
            }
        }


        // 2 - POST auth template to cause login
        $request = $this->requestFactory->createRequest('POST', $this->base.static::URL_AUTH)
            ->withBody($this->streamFactory->createStream(json_encode($authBody)))
            ->withAddedHeader('Cookie', $authCookie)
            ->withHeader('Content-Type', 'application/json');
        $response = $this->client->sendRequest($request);
        $loginBody = json_decode($response->getBody()->getContents());

        if ($response->getStatusCode() >= 400) {
            $message = ((isset($loginBody->reason))
                ? $loginBody->reason . ': '
                : ''
            ) . ($loginBody->message ?? '') 
            . ' (' . $response->getStatusCode() . ')';
            throw new LoginException(                
                $message,
                $response->getStatusCode()
            );
        }

        $destination = $loginBody->successUrl;

        $response = $response->withAddedHeader('x-login-redirection', $destination);
        return $response;
        
    }

    public function validate($cookiesOrToken)
    {
        $token = null;
        if (is_array($cookiesOrToken)) {
            if (isset($cookiesOrToken['iPlanetDirectoryPro'])) {
                $token = $cookiesOrToken['iPlanetDirectoryPro'];
            }
            else {
                foreach ($cookiesOrToken as $setCookie) {
                    [$name, $value] = explode('=', $setCookie, 2);
                    if (trim($name) == 'iPlanetDirectoryPro') {
                        $token = explode(';', trim($value))[0];
                    }
                }
            }
        }
        elseif (is_string($cookiesOrToken)) {
            $token = $cookiesOrToken;
        }

        if (is_null($token)) {
            throw new \InvalidArgumentException('Unable to determine IdP token from provided input');
        }

        $body = (object)['tokenId' => $token];
        $request = $this->requestFactory->createRequest('POST', $this->base.static::URL_VALIDATE)
            ->withBody($this->streamFactory->createStream(json_encode($body)))
            ->withHeader('Content-Type', 'application/json');
        $response = $this->client->sendRequest($request);

        if ($response->getStatusCode() == 200) {
            $tokenInfo = json_decode($response->getBody()->getContents());
            return (is_object($tokenInfo) && $tokenInfo->valid); // == true
        }
        
        return false;
    }

    public function getLoginSessionCookies(ResponseInterface $loginResponse)
    {
        return array_map(function($el) {
            return explode(';', $el)[0];
        }, $loginResponse->getHeaders()['set-cookie']);
    }


}