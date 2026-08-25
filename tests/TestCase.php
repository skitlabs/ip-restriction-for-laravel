<?php

declare(strict_types=1);

namespace Skitlabs\IpRestriction\Tests;

use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase as Orchestra;
use Skitlabs\IpRestriction\IpRestrictionServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            IpRestrictionServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        Config::set('ip_restriction.ignored_environments', []);
        Config::set('ip_restriction.logging.level', 'none');
    }
}
