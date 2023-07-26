<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers;

use Tymon\JWTAuth\Factory;
use Tymon\JWTAuth\Http\Parser\AuthHeaders;
use Tymon\JWTAuth\Http\Parser\Cookies;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Http\Parser\RouteParams;

class LaravelServiceProvider extends AbstractServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function boot()
    {
        $path = realpath(__DIR__.'/../../config/config.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        $this->aliasMiddleware();

        $this->extendAuthGuard();
    }

    /**
     * {@inheritdoc}
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('tymon.jwt.provider.storage', function () {
            $instance = $this->getConfigInstance('providers.storage');

            if (method_exists($instance, 'setLaravelVersion')) {
                $instance->setLaravelVersion($this->app->version());
            }

            return $instance;
        });
    }

    /**
     * Alias the middleware.
     *
     * @return void
     */
    protected function aliasMiddleware()
    {
        $router = $this->app['router'];

        $method = method_exists($router, 'aliasMiddleware') ? 'aliasMiddleware' : 'middleware';

        foreach ($this->middlewareAliases as $alias => $middleware) {
            $router->$method($alias, $middleware);
        }
    }

    protected function registerTokenParser()
    {
        $this->app->singleton('tymon.jwt.parser', function ($app) {
            $parser = new Parser(
                $app['request'],
                [
                    new AuthHeaders,
                    (new Cookies($this->config('decrypt_cookies')))->setKey($this->config('token_key')),
                ]
            );

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

    protected function registerPayloadFactory()
    {
        $this->app->singleton('tymon.jwt.payload.factory', function ($app) {
            return (new Factory(
                $app['tymon.jwt.claim.factory'],
                $app['tymon.jwt.validators.payload']
            ))->setDefaultClaims([
                'iat',
                'exp',
                'nbf',
                'jti',
            ]);
        });
    }
}
