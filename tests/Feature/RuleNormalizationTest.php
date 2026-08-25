<?php

declare(strict_types=1);

namespace Skitlabs\IpRestriction\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Skitlabs\IpRestriction\Http\Middleware\AllowIpAddresses;
use Skitlabs\IpRestriction\Tests\TestCase;

class RuleNormalizationTest extends TestCase
{
    #[Test]
    public function it_normalizes_messy_comma_separated_strings(): void
    {
        $definition = (string) AllowIpAddresses::configure(' 10.10.10.10 , 10.10.10.11, ');

        $this->assertSame('ip.allow:10.10.10.10,10.10.10.11', $definition);
    }

    #[Test]
    public function it_handles_messy_route_arguments(): void
    {
        $route = '/'.__FUNCTION__;

        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:  log:none ,  10.20.20.20  , channel:security,  ');

        $this->withServerVariables(['REMOTE_ADDR' => '10.20.20.20'])
            ->get($route)
            ->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '8.8.8.8'])
            ->get($route)
            ->assertForbidden();
    }

    #[Test]
    public function it_resolves_config_groups_defined_as_messy_comma_separated_strings(): void
    {
        // Simulating a config group pulled directly from a messy .env variable
        Config::set('ip_restriction.groups.messy_env', '10.30.30.30, 10.40.40.40, , ');

        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:messy_env');

        $this->withServerVariables(['REMOTE_ADDR' => '10.40.40.40'])
            ->get($route)
            ->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '8.8.8.8'])
            ->get($route)
            ->assertForbidden();
    }

    #[Test]
    public function it_flattens_deeply_nested_arrays_and_strings_in_configuration(): void
    {
        Config::set('ip_restriction.groups.nested_group', [
            '10.50.50.50',
            ['10.60.60.60', '10.70.70.70'],
            ' 10.80.80.80, 10.90.90.90  ,  ',
        ]);

        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:nested_group');

        // Assert a standard string works
        $this->withServerVariables(['REMOTE_ADDR' => '10.50.50.50'])
            ->get($route)
            ->assertOk();

        // Assert a value from the nested array works
        $this->withServerVariables(['REMOTE_ADDR' => '10.70.70.70'])
            ->get($route)
            ->assertOk();

        // Assert the comma-separated string inside the array works
        $this->withServerVariables(['REMOTE_ADDR' => '10.90.90.90'])
            ->get($route)
            ->assertOk();

        // Assert other IP fails
        $this->withServerVariables(['REMOTE_ADDR' => '8.8.8.8'])
            ->get($route)
            ->assertForbidden();
    }

    #[Test]
    public function it_supports_direct_cidr_injection_with_spaces(): void
    {
        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow: 10.0.0.0/8 , 192.168.1.0/24');

        $this->withServerVariables(['REMOTE_ADDR' => '10.5.5.5'])
            ->get($route)
            ->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.100'])
            ->get($route)
            ->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '172.16.0.1'])
            ->get($route)
            ->assertForbidden();
    }
}
