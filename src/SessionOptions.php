<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-session
 */
declare(strict_types=1);

namespace froq\session;

/**
 * Session options with defaults.
 *
 * @package froq\session
 * @object  froq\session\SessionOptions
 * @author  Kerem Güneş
 * @since   6.0
 */
class SessionOptions extends \Options
{
    /**
     * Create session options with defaults.
     *
     * @param  array|null $options
     * @return froq\session\SessionOptions
     */
    public static function create(array|null $options): SessionOptions
    {
        static $optionsDefault = [
            'name'     => 'SID',
            'hash'     => false, 'hashLength'  => 32, 'hashUpper' => false,
            'savePath' => null,  'saveHandler' => null,
            'cookie'   => [
                'lifetime' => 0,     'path'     => '/',   'domain'   => '',
                'secure'   => false, 'httponly' => false, 'samesite' => '',
            ]
        ];

        // Create & filter base options.
        $that = (new SessionOptions($options, $optionsDefault))
            ->filterDefaultKeys($optionsDefault);
        $that->name = trim((string) $that->name);

        // Create & filter cookie options.
        $that->cookie = (new SessionOptions($that->cookie))
            ->filterDefaultKeys($optionsDefault['cookie']);

        return $that;
    }
}
