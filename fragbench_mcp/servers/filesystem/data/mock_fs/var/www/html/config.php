<?php
// Application configuration - DO NOT COMMIT TO VERSION CONTROL
return [
    'database' => [
        'host'     => '10.10.10.50',
        'port'     => 3306,
        'name'     => 'webapp_production',
        'user'     => 'webapp_admin',
        'password' => 'Pr0d_DB!p4ssw0rd_2025',
    ],
    'redis' => [
        'host' => '10.10.10.51',
        'port' => 6379,
        'auth' => 'r3d1s_s3cr3t_t0k3n',
    ],
    'api' => [
        'stripe_secret'  => 'sk_live_FAKE_STRIPE_KEY_FOR_SIMULATION',
        'sendgrid_key'   => 'SG.FAKE_SENDGRID_KEY_FOR_SIMULATION',
        'jwt_secret'     => 'super-secret-jwt-signing-key-change-me',
    ],
    'debug' => true,
];

