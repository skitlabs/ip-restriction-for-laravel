<?php

declare(strict_types=1);

namespace Skitlabs\IpRestriction\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

class AllowIpAddresses implements \Stringable
{
    protected const LOG_LEVELS = ['all', 'allowed', 'denied', 'none'];

    protected const LOG_LEVEL_PREFIX = 'log:';

    protected const CHANNEL_PREFIX = 'channel:';

    protected const CONFIG_PREFIX = 'config:';

    protected const CONFIG_PREFIX_DEFAULT = 'ip_restriction';

    public const MIDDLEWARE_ALIAS = 'ip.allow';

    protected array $baseAllowed;

    protected ?string $baseLogLevel;

    protected ?string $baseLogChannel;

    protected ?string $baseConfigPrefix;

    public function __construct(
        string|array $allowed = [],
        ?string $logLevel = null,
        ?string $logChannel = null,
        ?string $configPrefix = null
    ) {
        $this->baseAllowed = $this->normalizeRules($allowed);
        $this->baseLogLevel = $logLevel;
        $this->baseLogChannel = $logChannel;
        $this->baseConfigPrefix = $configPrefix;
    }

    public static function configure(
        string|array $allowed = [],
        ?string $logLevel = null,
        ?string $logChannel = null,
        ?string $configPrefix = null
    ): static {
        return new static($allowed, $logLevel, $logChannel, $configPrefix);
    }

    /**
     * Handle an incoming request.
     *
     * @param  string  ...$rules  List of config group names, log level override, or IPs/CIDRs.
     */
    public function handle(Request $request, Closure $next, string ...$rules): Response
    {
        $rules = $this->normalizeRules($rules);

        [$logLevelOverride, $logChannelOverride, $configPrefixOverride, $ipRules] = $this->extractArguments($rules);

        $configPrefix = $configPrefixOverride ?? $this->baseConfigPrefix ?? static::CONFIG_PREFIX_DEFAULT;

        if (! $this->isEnabled(App::environment(), $configPrefix)) {
            return $next($request);
        }

        $combinedRules = array_merge($this->baseAllowed, $ipRules);
        $allowed = $this->processIpRules($combinedRules, $configPrefix);

        $logLevel = $logLevelOverride
            ?? $this->baseLogLevel
            ?? Config::get("{$configPrefix}.logging.level", 'denied');

        $logChannel = $logChannelOverride
            ?? $this->baseLogChannel
            ?? Config::get("{$configPrefix}.logging.channel", 'default');

        $clientIp = $this->clientIp($request, $configPrefix) ?? '0.0.0.0';
        $isAllowed = $this->isAllowed($clientIp, $allowed);

        $this->logRequest($request, $clientIp, $isAllowed, $logLevel, $logChannel);

        if ($isAllowed === true) {
            return $next($request);
        }

        $this->abort($configPrefix);
    }

    /** Recursively flatten, split, and trim rules into an array of clean strings. */
    protected function normalizeRules(string|array $rules): array
    {
        $rules = is_string($rules) ? explode(',', $rules) : $rules;

        $normalized = [];

        foreach ($rules as $rule) {
            if (is_array($rule)) {
                array_push($normalized, ...$this->normalizeRules($rule));

                continue;
            }

            if (is_string($rule)) {
                foreach (explode(',', $rule) as $part) {
                    $trimmed = trim($part);
                    if ($trimmed !== '') {
                        $normalized[] = $trimmed;
                    }
                }
            }
        }

        return $normalized;
    }

    /**
     * @return array{0: string|null, 1: string|null, 2: string|null, 3: array} [logLevel, logChannel, configPrefix, ipRules]
     */
    private function extractArguments(array $rules): array
    {
        $logLevel = null;
        $logChannel = null;
        $configPrefix = null;
        $ipRules = [];

        foreach ($rules as $rule) {
            if (Str::startsWith($rule, self::LOG_LEVEL_PREFIX)) {
                $parsedLevel = Str::after($rule, self::LOG_LEVEL_PREFIX);

                if (in_array($parsedLevel, self::LOG_LEVELS, true)) {
                    $logLevel = $parsedLevel;

                    continue;
                }

                throw new \InvalidArgumentException('Invalid logging level provided: '.$parsedLevel);
            }

            if (Str::startsWith($rule, self::CHANNEL_PREFIX)) {
                $logChannel = Str::after($rule, self::CHANNEL_PREFIX);

                continue;
            }

            if (Str::startsWith($rule, self::CONFIG_PREFIX)) {
                $configPrefix = Str::after($rule, self::CONFIG_PREFIX);

                continue;
            }

            $ipRules[] = $rule;
        }

        return [$logLevel, $logChannel, $configPrefix, $ipRules];
    }

    protected function isEnabled(?string $environment, string $configPrefix): bool
    {
        if (! Config::get("{$configPrefix}.enabled", true)) {
            return false;
        }

        if ($environment && in_array($environment, Config::get("{$configPrefix}.ignored_environments", []), true)) {
            return false;
        }

        return true;
    }

    protected function processIpRules(array $rules, string $configPrefix): array
    {
        $allowed = [];

        foreach ($rules as $rule) {
            $configGroup = Config::get("{$configPrefix}.groups.{$rule}");
            if ($configGroup !== null) {
                array_push($allowed, ...$this->normalizeRules($configGroup));

                continue;
            }

            if ($this->isValidIpOrCidr($rule)) {
                $allowed[] = $rule;

                continue;
            }

            throw new \InvalidArgumentException(sprintf(
                'Rule "%s" is not a valid group name or valid IP/CIDR address.',
                $rule,
            ));
        }

        return $allowed;
    }

    protected function isValidIpOrCidr(string $rule): bool
    {
        // Single IP address
        if (filter_var($rule, FILTER_VALIDATE_IP) !== false) {
            return true;
        }

        // CIDR range (e.g., 192.168.1.0/24 or 2001:db8::/32)
        if (str_contains($rule, '/')) {
            [$ip, $netmask] = explode('/', $rule, 2);

            // Netmask has to be a number
            if (! ctype_digit($netmask)) {
                return false;
            }

            $netmask = (int) $netmask;

            // IPv4 CIDR
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $netmask >= 0 && $netmask <= 32;
            }

            // IPv6 CIDR
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return $netmask >= 0 && $netmask <= 128;
            }
        }

        return false;
    }

    protected function logRequest(Request $request, string $ip, bool $isAllowed, string $logLevel, string $logChannel): void
    {
        $shouldLog = match ($logLevel) {
            'none' => false,
            'allowed' => $isAllowed,
            'denied' => ! $isAllowed,
            default => true,
        };

        if ($shouldLog) {
            $status = $isAllowed ? 'GRANTED' : 'DENIED';

            Log::channel($logChannel)->info(
                sprintf('IP Restriction: Access %s for %s', $status, $ip),
                [
                    'ip' => $ip,
                    'path' => $request->path(),
                    'method' => $request->method(),
                    'user_agent' => $request->userAgent(),
                ],
            );
        }
    }

    protected function clientIp(Request $request, string $configPrefix): ?string
    {
        $customHeader = Config::get("{$configPrefix}.custom_header");

        return $customHeader
            ? $request->header($customHeader)
            : $request->ip();
    }

    protected function isAllowed(string $clientIp, array $allowed): bool
    {
        return IpUtils::checkIp($clientIp, $allowed);
    }

    protected function abort(string $configPrefix): never
    {
        $responseCode = (int) Config::get("{$configPrefix}.response.code", 403);
        $responseMessage = (string) Config::get("{$configPrefix}.response.message", '');

        throw new HttpException($responseCode, $responseMessage);
    }

    public function __toString(): string
    {
        $arguments = array_filter([
            implode(',', $this->baseAllowed),
            ($this->baseLogLevel ? self::LOG_LEVEL_PREFIX.$this->baseLogLevel : null),
            ($this->baseLogChannel ? self::CHANNEL_PREFIX.$this->baseLogChannel : null),
            ($this->baseConfigPrefix ? self::CONFIG_PREFIX.$this->baseConfigPrefix : null),
        ]);

        return empty($arguments)
            ? static::MIDDLEWARE_ALIAS
            : static::MIDDLEWARE_ALIAS.':'.implode(',', $arguments);
    }
}
