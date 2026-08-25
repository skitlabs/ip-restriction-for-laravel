<?php

declare(strict_types=1);

namespace Skitlabs\IpRestriction\Http\Middleware;

class BlockIpAddresses extends AllowIpAddresses
{
    protected function isAllowed(string $clientIp, array $allowed): bool
    {
        return ! parent::isAllowed($clientIp, $allowed);
    }
}
