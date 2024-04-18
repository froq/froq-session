<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-session
 */
namespace froq\session;

use froq\common\interface\{Arrayable, Objectable};
use froq\common\trait\FactoryTrait;
use froq\file\PathInfo;
use froq\util\Util;
use Assert, Uuid;

/**
 * A session management class that utilies internal session stuff.
 *
 * @package froq\session
 * @class   froq\session\Session
 * @author  Kerem Güneş
 * @since   1.0
 */
class Session implements Arrayable, Objectable, \ArrayAccess
{
    use FactoryTrait;

    /** CSRF token prefix (appended as token key). */
    private const CSRF_TOKEN_PREFIX = '@csrf-token-';

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

    /** Session options with defaults. */
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
            Assert::true(trim($savePath) !== '', new SessionException(
                'Option "savePath" must not be empty'
            ));

            $pathInfo = new PathInfo($savePath);
            if ($pathInfo->isFile() || $pathInfo->isLink()) {
                throw new SessionException('Given path is a file / link [path: %s]', $pathInfo);
            } elseif ($pathInfo->isDirectory() && !$pathInfo->isAvailable()) {
                throw new SessionException('Given path is not readable / writable [path: %s]', $pathInfo);
            } elseif (!$pathInfo->isDirectory() && !@dirmake($pathInfo->getPath())) {
                throw new SessionException('Cannot make directory "savePath" option [path: %s, error: @error]',
                    $pathInfo, extract: true);
            }

            $this->savePath = $pathInfo->getPath();

            session_save_path($this->savePath);
        }

        if (isset($this->options['saveHandler'])) {
            $saveHandler = $this->options['saveHandler'];
            Assert::type($saveHandler, 'string|array', new SessionException(
                'Option "saveHandler" must be string|array, %t given', $saveHandler
            ));

            // When file given.
            if (is_array($saveHandler)) {
                @ [$saveHandler, $saveHandlerFile] = $saveHandler;
                if (!$saveHandler || !$saveHandlerFile) {
                    throw new SessionException(
                        'Both handler class and handler file are required '.
                        'when "saveHandler" option is array'
                    );
                }

                if (!is_file($saveHandlerFile)) {
                    throw new SessionException(
                        'Handler file not exists [file: %s]',
                        $saveHandlerFile
                    );
                }

                require_once $saveHandlerFile;
            }

            $class = new \XClass($saveHandler);
            $class->exists() || throw new SessionException(
                'Handler class %Q not found', $class
            );
            $class->extends(SessionHandler::class) || throw new SessionException(
                'Handler class %Q must extend class %Q', [$saveHandler, SessionHandler::class]
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

    /**
     * @magic
     */
    public function __set(string $key, mixed $value): void
    {
        $this->set($key, $value);
    }

    /**
     * @magic
     */
    public function __get(string $key): mixed
    {
        return $this->get($key);
    }

    /**
     * Get an option.
     *
     * @param  string $key
     * @return mixed
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
    public function start(): bool
    {
        if (headers_sent($file, $line)) {
            throw new SessionException(
                'Cannot use %s(), headers already sent at %s:%s',
                [__METHOD__, $file, $line]
            );
        }

        if (!$this->started || session_status() !== PHP_SESSION_ACTIVE) {
            $id     = (string) session_id();
            $name   = $this->options['name'];
            $update = false;

            if ($this->isValidId($id)) {
                // Pass, never happens, but obsession..
            } else {
                $id = (string) ($_COOKIE[$name] ?? '');

                if (!$this->isValidId($id) || !$this->isValidSource($id)) {
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

            if (!$this->started = session_start()) {
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

            // Init sub-array as reserved session area.
            $_SESSION[$this->name] ??= ['@' => $this->id];
        }

        return $this->started;
    }

    /**
     * End.
     *
     * @param  bool $deleteCookie
     * @return bool
     */
    public function end(bool $deleteCookie = true): bool
    {
        if (!$this->ended && !!$this->started) {
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
        // Forbid ID.
        if ($key === '@') {
            throw new SessionException('Cannot set key "@"');
        }

        $name = $this->name();

        if (!isset($_SESSION[$name])) {
            throw new SessionException('Session not started yet, call start()');
        }
        if (!is_array($_SESSION[$name])) {
            throw new SessionException('Session sub-array is corrupted');
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
        // Forbid ID.
        if ($key === '@') {
            throw new SessionException('Cannot get key "@", use id() instead');
        }

        $name = $this->name();

        if (!isset($_SESSION[$name])) {
            throw new SessionException('Session not started yet, call start()');
        }
        if (!is_array($_SESSION[$name])) {
            throw new SessionException('Session sub-array is corrupted');
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
        // Forbid ID.
        if ($key === '@') {
            throw new SessionException('Cannot remove key "@"');
        }

        $name = $this->name();

        if (!isset($_SESSION[$name])) {
            throw new SessionException('Session not started yet, call start()');
        }
        if (!is_array($_SESSION[$name])) {
            throw new SessionException('Session sub-array is corrupted');
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
     */
    public function flush(): void
    {
        $name = $this->name();

        if (isset($_SESSION[$name])) {
            $_SESSION[$name] = ['@' => $this->id()];
        }
    }

    /**
     * Check ID validity.
     *
     * @param  string $id
     * @return bool
     */
    public function isValidId(string $id): bool
    {
        // Prevents NULL-bytes too.
        if (!$this->validateId($id)) {
            return false;
        }

        $saveHandler = $this->saveHandler();
        if ($saveHandler && method_exists($saveHandler, 'isValidId')) {
            return $saveHandler->isValidId($id);
        }

        // Some other generate methods might be used.
        if ($saveHandler) {
            $generateId = match (true) {
                method_exists($saveHandler, 'generateId') => [$saveHandler, 'generateId'],
                session_status() === PHP_SESSION_ACTIVE   => [$saveHandler, 'create_sid'],
                default                                   => [$this, 'generateId'],
            };

            if ($generateId) {
                $gid = preg_remove('~[^a-z0-9]~i', $generateId());
                $sid = preg_remove('~[^a-z0-9]~i', $id);

                // Try possible ways.
                return strlen($gid) === strlen($sid) && (
                    (ctype_alnum($gid)  && ctype_alnum($sid))  ||
                    (ctype_xdigit($gid) && ctype_xdigit($sid)) ||
                    (ctype_digit($gid)  && ctype_digit($sid))
                );
            }
        }

        // Validate by UUID.
        if ($this->options['hash'] === 'uuid') {
            return Uuid::validate($id);
        }

        static $idPattern;

        if (!$idPattern) {
            if ($this->options['hash']) {
                $idPattern = sprintf(
                    '~^[A-F0-9]{%d}$~%s',
                    $this->options['hash'],
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
     * @param  string $id
     * @return bool
     */
    public function isValidSource(string $id): bool
    {
        // Prevents NULL-bytes too.
        if (!$this->validateId($id)) {
            return false;
        }

        $saveHandler = $this->saveHandler();
        if ($saveHandler && method_exists($saveHandler, 'isValidSource')) {
            return $saveHandler->isValidSource($id);
        }

        // @see https://github.com/php/php-src/blob/master/ext/session/mod_files.c#L85
        $sourceFile = ($this->savePath() ?? session_save_path()) . '/sess_' . $id;

        return file_exists($sourceFile);
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
            $id = Uuid::generate(true);

            if ($this->options['hashUpper']) {
                $id = strtoupper($id);
            }

            return $id;
        }

        $id = session_create_id();

        // Hash by length.
        if ($this->options['hash']) {
            $algo = match ((int) $this->options['hash']) {
                16 => 'fnv1a64', 32 => 'md5', 40 => 'sha1',
                default => throw new SessionException(
                    'Invalid "hash" option %Q [valids: 16, 32, 40, uuid]',
                    $this->options['hash']
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
     * Validate id (basically alpnum & dashes for UUIDs).
     *
     * @param  string $id
     * @return bool
     */
    public function validateId(string $id): bool
    {
        return $id && preg_test('~^[a-z0-9][a-z0-9-]+$~i', $id);
    }

    /**
     * Get a stored CSRF token for given key if exists.
     *
     * @param  string $key
     * @param  bool   $drop
     * @return string|null
     */
    public function getCsrfToken(string $key, bool $drop = false): string|null
    {
        $csrfKey   = self::CSRF_TOKEN_PREFIX . $key;
        $csrfToken = $this->get($csrfKey, null, $drop);

        return $csrfToken;
    }

    /**
     * Remove a stored CSRF token for given key if exists.
     *
     * @param  string $key
     * @param  bool   $drop
     * @return string|null
     */
    public function removeCsrfToken(string $key): bool
    {
        return $this->getCsrfToken($key, true) !== null;
    }

    /**
     * Generate a CSRF token for given key, write to session.
     *
     * @param  string     $key
     * @param  string|int $algo Algo or base.
     * @return string
     */
    public function generateCsrfToken(string $key, string|int $algo = 'md5'): string
    {
        $csrfKey   = self::CSRF_TOKEN_PREFIX . $key;
        $csrfToken = Uuid::generateHash(24, $algo);

        $this->set($csrfKey, $csrfToken);

        return $csrfToken;
    }

    /**
     * Validate a CSRF token for given key.
     *
     * @param  string $key
     * @param  string $token Retrieved externally.
     * @param  bool   $drop
     * @return bool
     */
    public function validateCsrfToken(string $key, string $token, bool $drop = false): bool
    {
        $csrfKey   = self::CSRF_TOKEN_PREFIX . $key;
        $csrfToken = $this->get($csrfKey, null, $drop);

        return $csrfToken && hash_equals($csrfToken, $token);
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

    /**
     * @inheritDoc ArrayAccess
     */
    public function offsetExists(mixed $key): bool
    {
        return $this->has($key);
    }

    /**
     * @inheritDoc ArrayAccess
     */
    public function offsetSet(mixed $key, mixed $value): void
    {
        $this->set($key, $value);
    }

    /**
     * @inheritDoc ArrayAccess
     */
    public function offsetGet(mixed $key): mixed
    {
        return $this->get($key);
    }

    /**
     * @inheritDoc ArrayAccess
     */
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

    //     $res = @$func(...$funcArgs);
    //     if ($res === false) {
    //         throw new SessionException(error_message() ?: 'Unknown');
    //     }
    //     return $res;
    // }
}
