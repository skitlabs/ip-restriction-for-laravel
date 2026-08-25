# IP Restriction Middleware for Laravel

Configurable IP allow-/blocklist (white-/blacklist) middleware package for Laravel 12 and 13.   

Secure routes, groups, or the entire application using single IPs, CIDR ranges, or predefined configuration groups. Allows for per-route configuration overrides.   

## Features

* **Allow- & Blocklist:** Using the provided `ip.allow` and `ip.block` middleware.
* **CIDR Support:** Supports IPv4 and IPv6 CIDR ranges (e.g., `10.0.0.0/8`, `2001:db8::/32`).
* **Named Groups:** Group IPs in your config file (e.g., `office`, `webhooks`) for clean and reusable lists.
* **Route-Level Overrides:** Override log level, channel, and config prefixes directly in your route definitions.
* **Stateless & Octane Ready:** Compatible with long-running processes that handle multiple requests, like Laravel Octane.

## Requirements

* PHP `^8.3`
* Laravel `^12.0` or `^13.0`

## Installation

Install the package with composer:

```sh
composer require skitlabs/ip-restriction-for-laravel
```

Publish the configuration file:

```sh
php artisan vendor:publish --tag="ip-restriction-config"
```

This will create a `config/ip_restriction.php` file in your application.

## Usage
The package automatically registers two middleware aliases:

* `ip.allow` (Allow only the configured IPs, blocking all other requests)
* `ip.block` (Block only the configured IPs, allowing all other requests)

Apply the middleware directly to your routes or route groups in `routes/web.php` or `routes/api.php`:

```php
use Illuminate\Support\Facades\Route;

// Direct IP/CIDR configuration
Route::post('/api/internal', [Controller::class, 'handle'])
    ->middleware('ip.allow:192.168.1.50,10.0.0.0/16,::1');

// Mixed named groups and direct IPs
Route::get('/api/dashboard', [Controller::class, 'index'])
    ->middleware('ip.allow:office,203.0.113.20');

// Blacklisting bad actors
Route::post('/login', [Controller::class, 'attempt'])
    ->middleware('ip.block:known_bad_ips');
```

### Overrides
You can dynamically override middleware behavior per group or route. These overrides are resolved _before_ evaluating other configuration. The _last_ override wins.   

#### Logging
```php
// Log ALL attempts to the 'security' log channel
Route::post('/webhooks/stripe', [Controller::class, 'handle'])
    ->middleware('ip.allow:webhooks,log:all,channel:security');

// Disable logging entirely
Route::get('/health-check', [Controller::class, 'index'])
    ->middleware('ip.allow:monitoring,log:none');
```

#### Config Prefix
By using the `config:`-prefix, you can override the base configuration key. This can be useful when managing multiple domains (e.g., Admin Panel and API) that require different defaults.    
The following example would read configuration from `config/api_restrictions.php` instead.    

```php
Route::middleware(['ip.allow:config:api_restrictions,office'])->group(function () {
    // Middleware now uses `config/api_restrictions.php` to determine its defaults
});
```

### Global Middleware Registration
You can register the middleware globally, or configure it manually using the static `configure()`-method, in your bootstrap/app.php file. 

```php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;
use Skitlabs\IpRestriction\Http\Middleware\AllowIpAddress;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        // Append globally with dynamic configuration
        $middleware->append(
            AllowIpAddress::configure(
                allowed: ['office', '10.0.0.0/8'],
                logLevel: 'all',
                logChannel: 'security'
            )
        );
    })->create();
```

### Inline Middleware Configuration
Use the middleware's static `configure`-method, and pass an instance directly to your routes/groups.

```php
use Skitlabs\IpRestriction\Http\Middleware\AllowIpAddresses;

Route::get('/admin', [Controller::class, 'index'])
    ->middleware(AllowIpAddresses::configure(
        allowed: ['office', '127.0.0.1'], 
        logLevel: 'all',
    ));
```

## Configuration
The published `config/ip_restriction.php` allows control over how the middleware behaves:

```php
return [
    // Toggle the middleware globally
    'enabled' => env('IP_RESTRICTION_ENABLED', true),

    // Environments where the middleware will quietly pass (e.g., local development)
    'ignored_environments' => ['local', 'testing'],

    // Define reusable groups of IPs
    'groups' => [
        'office'   => ['192.168.1.0/24'],
        'webhooks' => ['198.51.100.14', '2001:0db8:85a3::/64'],
        'public'   => ['0.0.0.0/0', '::/0'],
        // Passing lists as strings is supported. Extra spaces or trailing commas are trimmed 
        'dynamic'  => env('ALLOWED_IPS', '192.168.1.50,  10.0.0.0/8, '), 
    ],

    // Configure the level and channel to log to
    'logging' => [
        'level'   => env('IP_RESTRICTION_LOG_LEVEL', 'denied'),
        'channel' => env('IP_RESTRICTION_LOG_CHANNEL', 'default'),
    ],

    // Configure the returned response, for when access has been denied
    'response' => [
        'code'    => 403,
        'message' => 'Access denied (IP)',
    ],
    
    // Specify custom header if behind a non-configured TrustedProxy (e.g., 'HTTP_CF_CONNECTING_IP')
    'custom_header' => null, 
];
```

## Testing
```sh
composer test
```

## License
The MIT License (MIT). Please see [License File](LICENSE) for more information.

