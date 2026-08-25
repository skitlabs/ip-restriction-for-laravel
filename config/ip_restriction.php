<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Enable / Disable Middleware
    |--------------------------------------------------------------------------
    */
    'enabled' => env('IP_RESTRICTION_ENABLED', true),

    'ignored_environments' => [],

    /*
    |--------------------------------------------------------------------------
    | Named IP Groups
    |--------------------------------------------------------------------------
    */
    'groups' => [
        // Allow all
        'public' => ['0.0.0.0/0', '::/0'],
        // Allow internal addresses
        'internal' => ['127.0.0.1', '::1', '10.0.0.0/8'],
        // Allow default docker traffic
        'docker' => ['172.23.0.5/16'],
        // Add custom groups; ...
        // 'webhooks' => ['198.51.100.14/32'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    */
    'logging' => [
        // One of; all, allowed, denied, none
        'level' => env('IP_RESTRICTION_LOG_LEVEL', 'denied'),
        'channel' => env('IP_RESTRICTION_LOG_CHANNEL', 'default'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Abort Response
    |--------------------------------------------------------------------------
    */
    'response' => [
        'code' => 403,
        'message' => 'Access denied (IP)',
    ],

    /*
    |--------------------------------------------------------------------------
    | Client IP / Proxy
    |--------------------------------------------------------------------------
    | When behind a proxy, and not using Laravel's TrustedProxy feature, you
    | can override the variable used to determine the client IP
    | (e.g., 'HTTP_CF_CONNECTING_IP' or 'HTTP_X_FORWARDED_FOR').
    */
    'custom_header' => null,
];
