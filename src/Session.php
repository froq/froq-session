<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-session
 */
declare(strict_types=1);

namespace froq\session;

use froq\common\interface\{Arrayable, Objectable};
use froq\common\trait\FactoryTrait;
use froq\file\system\Path;
use froq\encrypting\Uuid;
use froq\util\Util;
use Assert, XClass;

/**
 * A session management class that utilies internal session stuff.
 *
 * @package froq\session
 * @object  froq\session\Session
 * @author  Kerem Güneş
 * @since   1.0
 */
class Session implements Arrayable, Objectable, \ArrayAccess
{
    use FactoryTrait;

    /** Session ID. */
    private readonly string $id;

    /** Session name. */
    private readonly string $name;

    /** Session save path. */
    private readonly string $savePath;

    /** Session save handler. */
    private readonly object $saveHandler;

    /** Session started state. */
    private ?bool $started = null;

    /** Session ended state. */
    private ?bool $ended = null;

    /** Options with defaults. */
    private SessionOptions $options;

    /**
     * Constructor.
     *
     * @param  array|null $options
     * @throws froq\session\SessionException
     */
    public function __construct(array $options = null)
    {
        $this->options = SessionOptions::create($options);

        // Validate name.
        preg_test('~^([\w][\w\.\-]*)$~', $this->options['name'])
            || throw new SessionException('Session name must be alphanumeric & non-empty string');

        if (isset($this->options['savePath'])) {
            $savePath = $this->options['savePath'];
            Assert::type($savePath, 'string', new SessionException(
                'Option "savePath" must be string, %t given', $savePath
            ));
            Assert::true(trim($savePath) != '', new SessionException(
                'Option "savePath" must not be empty'
            ));

            $path = new Path($savePath);
            if ($path->isFile() || $path->isLink()) {
                throw new SessionException('Given path is a file / link [path: %s]', $path);
            } elseif ($path->isDirectory() && !$path->isAvailable()) {
                throw new SessionException('Given path is not readable / writable [path: %s]', $path);
            } elseif (!$path->isDirectory() && !$path->makeDirectory()) {
                throw new SessionException('Cannot make directory "savePath" option [path: %s, error: %s]',
                    [$path, '@error']);
            }

            // Update with real path.
            $this->savePath = $path->path;

            session_save_path($this->savePath);
        }

        if (isset($this->options['saveHandler'])) {
            $saveHandler = $this->options['saveHandler'];
            Assert::type($saveHandler, 'string|array', new SessionException(
                'Option "saveHandler" must be string|array, %t given', $saveHandler
            ));

            // When file given.
            if (is_array($saveHandler)) {
                [$saveHandler, $saveHandlerFile] =@ $saveHandler;
                if (!$saveHandler || !$saveHandlerFile) {
                    throw new SessionException(
                        'Both handler and handler file are required '.
                        'when "saveHandler" option is array'
                    );
                }

                $path = new Path($saveHandlerFile);
                $path->isFile() || throw new SessionException(
                    'Handler file not exists / not a file [file: %s, type: %s]',
                    [$path, $path->type ?: 'null']
                );

                // Update with real path.
                $saveHandlerFile = $path->path;

                require_once $saveHandlerFile;
            }

            $class = new XClass($saveHandler);
            $class->exists() || throw new SessionException(
                'Handler class %q not found', $class
            );
            $class->extends(AbstractHandler::class) || throw new SessionException(
                'Handler class %q must extend class %q', AbstractHandler::class
            );

            $this->saveHandler = $class->init($this);

            session_set_save_handler($this->saveHandler);
        }

        // Set cookie defaults.
        session_set_cookie_params((array) $this->options['cookie'] ?: session_get_cookie_params());
    }

    /**
     * Destructor.
     */
    public function __destruct()
    {
        session_register_shutdown();
    }

    /** @magic */
    public function __set(string $key, mixed $value): void
    {
        $this->set($key, $value);
    }

    /** @magic */
    public function __get(string $key): mixed
    {
        return $this->get($key);
    }

    /**
     * Get an option.
     *
     * @param  string $key
     * @return mixed
     * @since  6.0
     */
    public function option(string $key): mixed
    {
        if (strpos($key, '.')) {
            [$key, $subkey] = split('.', $key, 2);
            return $this->options[$key][$subkey] ?? null;
        }

        return $this->options[$key] ?? null;
    }

    /**
     * Get id.
     *
     * @return string|null
     */
    public function id(): string|null
    {
        return $this->id ?? null;
    }

    /**
     * Get name.
     *
     * @return string|null
     */
    public function name(): string|null
    {
        return $this->name ?? null;
    }

    /**
     * Get save path.
     *
     * @return string|null
     */
    public function savePath(): string|null
    {
        return $this->savePath ?? null;
    }

    /**
     * Get save handler.
     *
     * @return object|null
     */
    public function saveHandler(): object|null
    {
        return $this->saveHandler ?? null;
    }

    /**
     * Get cookie.
     *
     * @return array
     * @since  4.1
     */
    public function cookie(): array
    {
        $name  = $this->name();
        $value = $_COOKIE[$name] ?? null;

        return [$name, $value];
    }

    /**
     * Get cookie params.
     *
     * @param  bool $swap
     * @return array
     * @since  4.1
     */
    public function cookieParams(bool $swap = true): array
    {
        $cookieParams = session_get_cookie_params();

        // Fix: "Unrecognized key 'lifetime' found".
        $swap && array_swap($cookieParams, 'lifetime', 'expires');

        return $cookieParams;
    }

    /**
     * Check started state.
     *
     * @return bool|null
     */
    public function started(): bool|null
    {
        return $this->started;
    }

    /**
     * Check ended state.
     *
     * @return bool|null
     */
    public function ended(): bool|null
    {
        return $this->ended;
    }

    /**
     * Start.
     *
     * @return bool
     * @throws froq\session\SessionException
     */
    public function start(): bool|null
    {
        if (headers_sent($file, $line)) {
            throw new SessionException(
                'Cannot use %s(), headers already sent at %s:%s',
                [__METHOD__, $file, $line]
            );
        }

        if (!$this->started || session_status() != PHP_SESSION_ACTIVE) {
            $id     = session_id();
            $name   = $this->options['name'];
            $update = false;

            if ($id && $this->isValidId($id)) {
                // Pass, never happens, but obsession..
            } else {
                // Hard and hard.
                $id = $_COOKIE[$name] ?? '';
                if (!$id || !$this->isValidId($id) || !$this->isValidSource($id)) {
                    $id     = $this->generateId();
                    $update = true;
                }
            }

            // Set id & name.
            $this->id   = $id;
            $this->name = $name;

            // Must to be called before session_start().
            if ($update && session_id($this->id) === false) {
                throw new SessionException('@error');
            }
            if (session_name($this->name) === false) {
                throw new SessionException('@error');
            }

            $this->started = session_start();
            if (!$this->started) {
                session_write_close();
                throw new SessionException('@error');
            }

            // Id & name matches.
            if ($this->id !== session_id()) {
                session_write_close();
                throw new SessionException('Session ID match failed');
            }
            if ($this->name !== session_name()) {
                session_write_close();
                throw new SessionException('Session name match failed');
            }

            // Init sub-array.
            isset($_SESSION[$this->name]) || $_SESSION[$this->name] = ['@' => $this->id];
        }

        return $this->started;
    }

    /**
     * End.
     *
     * @param  bool $deleteCookie
     * @return bool|null
     */
    public function end(bool $deleteCookie = true): bool|null
    {
        if (!$this->ended && $this->started) {
            $this->ended = session_destroy();

            // Delete session cookie.
            if ($deleteCookie) {
                setcookie($this->name(), '', $this->cookieParams());
            }
        }

        return $this->ended;
    }

    /**
     * Check a var existence with given key.
     *
     * @param  string $key
     * @return bool
     */
    public function has(string $key): bool
    {
        $name = $this->name();

        return isset($_SESSION[$name][$key]);
    }

    /**
     * Put a var into session data.
     *
     * @param  string|array<string, mixed> $key
     * @param  mixed|null                  $value
     * @return self
     * @throws froq\session\SessionException
     */
    public function set(string|array $key, mixed $value = null): self
    {
        // Prevent ID.
        if ($key === '@') {
            throw new SessionException('Cannot modify key "@"');
        }

        $name = $this->name();
        if (!isset($_SESSION[$name])) {
            throw new SessionException('Session not started yet, call start()');
        }

        array_set($_SESSION[$name], $key, $value);

        return $this;
    }

    /**
     * Get a var from session data.
     *
     * @param  string|array<string> $key
     * @param  mixed|null           $default
     * @param  bool                 $drop
     * @return mixed
     * @throws froq\session\SessionException
     */
    public function get(string|array $key, mixed $default = null, bool $drop = false): mixed
    {
        // Prevent ID.
        if ($key === '@') {
            throw new SessionException('Cannot get key "@", use id() instead');
        }

        $name = $this->name();
        if (!isset($_SESSION[$name])) {
            throw new SessionException('Session not started yet, call start()');
        }

        return array_get($_SESSION[$name], $key, $default, $drop);
    }

    /**
     * Remove a var from session data.
     *
     * @param  string|array<string> $key
     * @return self
     * @throws froq\session\SessionException
     */
    public function remove(string|array $key): self
    {
        // Prevent ID.
        if ($key === '@') {
            throw new SessionException('Cannot remove key "@"');
        }

        $name = $this->name();
        if (!isset($_SESSION[$name])) {
            throw new SessionException('Session not started yet, call start()');
        }

        array_remove($_SESSION[$name], $key);

        return $this;
    }

    /**
     * Flash.
     *
     * @param  mixed|null $message
     * @return mixed (or self)
     */
    public function flash(mixed $message = null): mixed
    {
        return func_num_args()
             ? $this->set('@flash', $message)
             : $this->get('@flash', drop: true);
    }

    /**
     * Flush.
     *
     * @return void
     * @since 4.2
     */
    public function flush(): void
    {
        foreach (array_keys($this->array()) as $key) {
            ($key !== '@') && $this->remove($key);
        }
    }

    /**
     * Check ID validity.
     *
     * @param  string|null $id
     * @return bool
     */
    public function isValidId(string|null $id): bool
    {
        $id = trim((string) $id);
        if (!$id) {
            return false;
        }

        $saveHandler = $this->saveHandler();
        if ($saveHandler && method_exists($saveHandler, 'isValidId')) {
            return $saveHandler->isValidId($id);
        }

        // Validate by UUID.
        if ($this->options['hash'] === 'uuid') {
            if ($this->options['hashUpper']) {
                $id = strtolower($id);
            }

            return Uuid::isValid($id);
        }

        static $idPattern; if (!$idPattern) {
            if ($this->options['hash']) {
                $idPattern = sprintf(
                    '~^[A-F0-9]{%d}$~%s',
                    $this->options['hashLength'],
                    $this->options['hashUpper'] ? '' : 'i',
                );
            } else {
                // @see http://php.net/manual/en/session.configuration.php#ini.session.sid-length
                // @see http://php.net/manual/en/session.configuration.php#ini.session.sid-bits-per-character
                // @see https://github.com/php/php-src/blob/PHP-7.1/UPGRADING#L114
                $idLenDefault = '26';
                $idBpcDefault = '5';

                $idLen = ini_get('session.sid_length') ?: $idLenDefault;
                $idBpc = ini_get('session.sid_bits_per_character');
                if (!$idBpc) {
                    ini_set('session.sid_length', $idLenDefault);
                    ini_set('session.sid_bits_per_character', ($idBpc = $idBpcDefault));
                }

                $idChars = match ($idBpc) {
                    '4' => '0-9a-f', '5' => '0-9a-v',
                    '6' => '0-9a-zA-Z-,', default => ''
                };

                $idPattern = '~^[' . $idChars . ']{' . $idLen . '}$~';
            }
        }

        return preg_test($idPattern, $id);
    }

    /**
     * Check source validity.
     *
     * @param  string|null $id
     * @return bool
     */
    public function isValidSource(string|null $id): bool
    {
        $id = trim((string) $id);
        if (!$id) {
            return false;
        }

        $saveHandler = $this->saveHandler();
        if ($saveHandler && method_exists($saveHandler, 'isValidSource')) {
            return $saveHandler->isValidSource($id);
        }

        // For 'sess_' @see https://github.com/php/php-src/blob/master/ext/session/mod_files.c#L85
        return is_file(($this->savePath() ?? session_save_path()) .'/sess_'. $id);
    }

    /**
     * Generate ID.
     *
     * @return string
     * @throws froq\session\SessionException
     */
    public function generateId(): string
    {
        $saveHandler = $this->saveHandler();
        if ($saveHandler && method_exists($saveHandler, 'generateId')) {
            return $saveHandler->generateId();
        }

        // Hash is UUID.
        if ($this->options['hash'] === 'uuid') {
            $id = Uuid::generateWithTimestamp();
            if ($this->options['hashUpper']) {
                $id = strtoupper($id);
            }

            return $id;
        }

        $id = session_create_id();

        // Hash by length.
        if ($this->options['hash']) {
            $algo = match ((int) $this->options['hashLength']) {
                32 => 'md5', 40 => 'sha1', 16 => 'fnv1a64',
                default => throw new SessionException(
                    'Invalid "hashLength" option %q [valids: 32,40,16]',
                    $this->options['hashLength']
                )
            };

            $id = hash($algo, $id);

            if ($this->options['hashUpper']) {
                $id = strtoupper($id);
            }
        }

        return $id;
    }

    /**
     * Generate a CSRF token for a form & write to session.
     *
     * @param  string $form
     * @return string
     * @since  5.0
     */
    public function generateCsrfToken(string $form): string
    {
        $form      = '@form@' . $form;
        $formToken = Uuid::generateHash();

        $this->set($form, $formToken);

        return $formToken;
    }

    /**
     * Validate a CSRF token for a form which was previously written to session.
     *
     * @param  string $form
     * @param  string $token
     * @return bool
     * @since  5.0
     */
    public function validateCsrfToken(string $form, string $token): bool
    {
        $form      = '@form@' . $form;
        $formToken = $this->get($form);

        return $formToken && hash_equals($formToken, $token);
    }

    /**
     * @inheritDoc froq\common\interface\Arrayable
     */
    public function toArray(bool $deep = true): array
    {
        return Util::makeArray($this->array(), $deep);
    }

    /**
     * @inheritDoc froq\common\interface\Objectable
     */
    public function toObject(bool $deep = true): object
    {
        return Util::makeObject($this->array(), $deep);
    }

    /** @inheritDoc ArrayAccess */
    public function offsetExists(mixed $key): bool
    {
        return $this->has($key);
    }

    /** @inheritDoc ArrayAccess */
    public function offsetSet(mixed $key, mixed $value): void
    {
        $this->set($key, $value);
    }

    /** @inheritDoc ArrayAccess */
    public function offsetGet(mixed $key): mixed
    {
        return $this->get($key);
    }

    /** @inheritDoc ArrayAccess */
    public function offsetUnset(mixed $key): void
    {
        $this->remove($key);
    }

    /**
     * Internal array maker.
     */
    private function array(): array
    {
        return $_SESSION[$this->name()] ?? [];
    }

    // /**
    //  * Safe call for headers & sess_*() functions related errors. @keep
    //  */
    // private function call(callable $func = null, mixed ...$funcArgs): mixed
    // {
    //     if (headers_sent($file, $line)) {
    //         throw new SessionException(
    //             'Cannot use %s(), headers already sent at %s:%s',
    //             [$func, $file, $line]
    //         );
    //     }

    //     $res =@ $func(...$funcArgs);
    //     if ($res === false) {
    //         throw new SessionException(error_message() ?: 'Unkown');
    //     }
    //     return $res;
    // }
}
