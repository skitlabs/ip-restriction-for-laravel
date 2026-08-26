<?php

declare(strict_types=1);

namespace Skitlabs\IpRestriction\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Skitlabs\IpRestriction\Http\Middleware\AllowIpAddresses;
use Skitlabs\IpRestriction\Http\Middleware\BlockIpAddresses;

class MiddlewareStringableTest extends TestCase
{
    #[Test]
    public function it_casts_to_string_with_only_allowed_ips(): void
    {
        $middleware = AllowIpAddresses::configure(['127.0.0.1', 'office']);

        $this->assertSame('ip.allow:127.0.0.1,office', (string) $middleware);
    }

    #[Test]
    public function it_casts_to_string_with_only_a_log_directive(): void
    {
        $middleware = AllowIpAddresses::configure(logLevel: 'none');

        $this->assertSame('ip.allow:log:none', (string) $middleware);
    }

    #[Test]
    public function it_casts_to_string_with_all_arguments_combined(): void
    {
        $middleware = AllowIpAddresses::configure(
            rules: ['10.0.0.0/8', 'partners'],
            logLevel: 'all',
            logChannel: 'security',
            configPrefix: 'api_restriction'
        );

        $this->assertSame(
            'ip.allow:10.0.0.0/8,partners,log:all,channel:security,config:api_restriction',
            (string) $middleware
        );
    }

    #[Test]
    public function it_casts_to_string_without_any_arguments(): void
    {
        $middleware = AllowIpAddresses::configure();

        $this->assertSame('ip.allow', (string) $middleware);
    }

    #[Test]
    public function it_inherits_and_casts_the_blacklist_alias_correctly(): void
    {
        $middleware = BlockIpAddresses::configure('bad_actors', logChannel: 'slack');

        $this->assertSame('ip.block:bad_actors,channel:slack', (string) $middleware);
    }
}
