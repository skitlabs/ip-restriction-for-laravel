<?php

declare(strict_types=1);

namespace Skitlabs\IpRestriction\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Skitlabs\IpRestriction\Http\Middleware\AllowIpAddresses;
use Skitlabs\IpRestriction\Tests\TestCase;

class AllowIpAddressTest extends TestCase
{
    #[Test]
    public function it_does_not_allow_access_by_default(): void
    {
        $route = '/'.__FUNCTION__;
        Route::middleware('ip.allow')
            ->get($route, static fn (): string => 'success');

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get($route)
            ->assertClientError()
            ->assertDontSee('success');
    }

    #[Test]
    public function it_allows_access_to_a_whitelisted_direct_ip(): void
    {
        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:127.0.0.1');

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get($route)
            ->assertOk()
            ->assertSee('success');
    }

    #[Test]
    public function it_denies_access_to_an_unlisted_ip(): void
    {
        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:127.0.0.1');

        $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.99'])
            ->get($route)
            ->assertForbidden()
            ->assertDontSee('success');
    }

    #[Test]
    public function it_allows_access_via_a_configured_group(): void
    {
        $allowed = ['192.168.1.51', '192.168.1.50'];

        $group = __FUNCTION__;
        Config::set('ip_restriction.groups.'.$group, $allowed);

        $route = '/'.$group;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:'.$group);

        $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.50'])
            ->get($route)
            ->assertOk();
    }

    #[Test]
    public function it_allows_access_via_a_cidr_range(): void
    {
        $allowed = '10.0.0.0/8';

        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:'.$allowed);

        $this->withServerVariables(['REMOTE_ADDR' => '10.5.5.5'])
            ->get($route)
            ->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get($route)
            ->assertClientError();
    }

    #[Test]
    public function it_parses_and_applies_log_overrides(): void
    {
        Log::shouldReceive('channel')->with('security')->once()->andReturnSelf();
        Log::shouldReceive('info')->once()->withArgs(function ($message) {
            return str_contains($message, 'DENIED');
        });

        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:127.0.0.1,log:denied,channel:security');

        $this->withServerVariables(['REMOTE_ADDR' => '8.8.8.8'])
            ->get($route)
            ->assertForbidden();
    }

    #[Test]
    public function it_parses_and_applies_config_overrides(): void
    {
        Config::set(__FUNCTION__, [
            'enabled' => true,
            'ignored_environments' => [],
            'groups' => ['local' => ['127.0.0.1']],
            'logging' => [
                'level' => 'denied',
                'channel' => 'security',
            ],
            'response' => [
                'code' => 418,
                'message' => 'Only teapots allowed',
            ],
            'custom_header' => null,
        ]);
        Log::shouldReceive('channel')->with('security')->once()->andReturnSelf();
        Log::shouldReceive('info')->once()->withArgs(function ($message) {
            return str_contains($message, 'DENIED');
        });

        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:127.0.0.1,config:'.__FUNCTION__);

        $this->withServerVariables(['REMOTE_ADDR' => '8.8.8.8'])
            ->getJson($route)
            ->assertStatus(418)
            ->assertSee('Only teapots allowed');

        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:config:'.__FUNCTION__.',local');

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->getJson($route)
            ->assertOk();
    }

    #[Test]
    public function it_uses_configured_custom_header(): void
    {
        Config::set('ip_restriction.custom_header', 'X-Custom-Header');

        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:127.0.0.1');

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->getJson($route)
            ->assertForbidden();

        $this->withServerVariables(['X-Custom-Header' => '127.0.0.1'])
            ->getJson($route)
            ->assertForbidden();
    }

    #[Test]
    public function it_bypasses_middleware_if_environment_is_ignored(): void
    {
        Config::set('ip_restriction.ignored_environments', ['testing']);

        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:127.0.0.1');

        $this->withServerVariables(['REMOTE_ADDR' => '9.9.9.9'])
            ->get($route)
            ->assertOk();
    }

    #[Test]
    public function it_bypasses_middleware_when_disabled(): void
    {
        Config::set('ip_restriction.enabled', false);
        Config::set('ip_restriction.ignored_environments', []);

        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.allow:127.0.0.1');

        $this->withServerVariables(['REMOTE_ADDR' => '9.9.9.9'])
            ->get($route)
            ->assertOk();
    }

    #[Test]
    public function it_resolves_config_groups_passed_in_the_constructor(): void
    {
        $groupName = __FUNCTION__;
        Config::set('ip_restriction.groups', [
            $groupName => ['192.168.1.50'],
        ]);

        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware([AllowIpAddresses::configure($groupName)]);

        $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.50'])
            ->get($route)
            ->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '8.8.8.8'])
            ->get($route)
            ->assertForbidden();
    }
}
