<?php

declare(strict_types=1);

namespace Skitlabs\IpRestriction\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Skitlabs\IpRestriction\Tests\TestCase;

class BlockIpAddressTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::get('/blacklist-test', function () {
            return 'success';
        })->middleware('ip.block:192.168.1.100,office');
    }

    #[Test]
    public function it_does_not_block_access_by_default(): void
    {
        $route = '/'.__FUNCTION__;
        Route::middleware('ip.block')
            ->get($route, static fn (): string => 'success');

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get($route)
            ->assertOk()
            ->assertSee('success');
    }

    #[Test]
    public function it_blocks_a_blacklisted_direct_ip(): void
    {
        $blocked = '192.168.1.100';
        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.block:'.$blocked);

        $this->withServerVariables(['REMOTE_ADDR' => $blocked])
            ->get($route)
            ->assertForbidden();
    }

    #[Test]
    public function it_blocks_an_ip_from_a_blacklisted_group(): void
    {
        $blocked = ['192.168.1.51', '192.168.1.50'];

        $group = __FUNCTION__;
        Config::set('ip_restriction.groups.'.$group, $blocked);

        $route = '/'.$group;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.block:'.$group);

        $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.50'])
            ->get($route)
            ->assertForbidden();
    }

    #[Test]
    public function it_allows_access_to_any_unlisted_ip(): void
    {
        $blocked = '192.168.1.100';
        $route = '/'.__FUNCTION__;
        Route::get($route, static fn (): string => 'success')
            ->middleware('ip.block:'.$blocked);

        $this->withServerVariables(['REMOTE_ADDR' => '8.8.8.8'])
            ->get($route)
            ->assertOk();
    }
}
