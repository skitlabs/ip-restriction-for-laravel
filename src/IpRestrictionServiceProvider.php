<?php

declare(strict_types=1);

namespace Skitlabs\IpRestriction;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Skitlabs\IpRestriction\Http\Middleware\AllowIpAddresses;
use Skitlabs\IpRestriction\Http\Middleware\BlockIpAddresses;

class IpRestrictionServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/ip_restriction.php', 'ip_restriction'
        );
    }

    public function boot(Router $router): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/ip_restriction.php' => $this->app->configPath('ip_restriction.php'),
            ], 'ip-restriction-config');
        }

        // Automatically register route middleware aliases
        $router->aliasMiddleware('ip.allow', AllowIpAddresses::class);
        $router->aliasMiddleware('ip.block', BlockIpAddresses::class);
    }
}
