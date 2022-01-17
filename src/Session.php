<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-session
 */
declare(strict_types=1);

namespace froq\session;

use froq\session\{SessionException, AbstractHandler};
use froq\common\trait\OptionTrait;
use froq\common\interface\{Arrayable, Objectable};
use froq\util\{Util, Arrays};

/**
 * Session.
 *
 * @package froq\session
 * @object  froq\session\Session
 * @author  Kerem Güneş
 * @since   1.0
 */
final class Session implements Arrayable, Objectable
{
    /**
     * @see froq\common\trait\OptionTrait
     * @since 4.0
     */
    use OptionTrait;

    /** @var string */
    private string $id;

    /** @var string */
    private string $name;

    /** @var string */
    private string $savePath;

    /** @var object */
    private object $saveHandler;

    /** @var bool */
    private bool|null $started = null;

    /** @var bool */
    private bool|null $ended = null;

    /** @var array */
    private static array $optionsDefault = [
        'name'     => 'SID',
        'hash'     => false, 'hashLength'  => null, 'hashUpper' => false,
        'savePath' => null,  'saveHandler' => null,
        'cookie'   => [
            'lifetime' => 0,     'path'     => '/',   'domain'   => '',
            'secure'   => false, 'httponly' => false, 'samesite' => '',
        ]
    ];

    /**
     * Constructor.
     *
     * @param  array<string, any>|null $options
     * @throws froq\session\SessionException
     */
    public function __construct(array $options = null)
    {
        $options = Arrays::options($options, self::$optionsDefault);
        $options['cookie'] = Arrays::mapKeys($options['cookie'], 'strtolower');

        $this->setOptions($options);

        $savePath = $options['savePath'];
        if ($savePath != null) {
            if (!is_dir($savePath) && !mkdir($savePath, 0755, true)) {
                throw new SessionException('Cannot make directory `%s` for `savePath` option [error: %s]',
                    [$savePath, '@error']);
            }

            session_save_path($savePath);
            $this->savePath = $savePath;
        }

        $saveHandler = $options['saveHandler'];
        if ($saveHandler != null) {
            // When file given.
            if (is_array($saveHandler)) {
                @ [$saveHandler, $saveHandlerFile] = $saveHandler;
                if ($saveHandler == null || $saveHandlerFile == null) {
                    throw new SessionException('Both handler and handler file are required when `saveHandler`'
                        . ' option is array');
                }

                if (!is_file($saveHandlerFile)) {
                    throw new SessionException('Could not find given handler file `%s`', $saveHandlerFile);
                }

                require_once $saveHandlerFile;
            }

            // Class validity checks.
            class_exists($saveHandler) || throw new SessionException(
                'Handler class `%s` not found', $saveHandler
            );
            class_extends($saveHandler, AbstractHandler::class) || throw new SessionException(
                'Handler class must extend `%s` class', AbstractHandler::class
            );

            // Init & save/set handler.
            session_set_save_handler($saveHandler = new $saveHandler($this));
            $this->saveHandler = $saveHandler;
        }

        // Set cookie defaults.
        session_set_cookie_params($options['cookie'] ?: session_get_cookie_params());
    }

    /**
     * Destructor.
     */
    public function __destruct()
    {
        session_register_shutdown();
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
        $swap && Arrays::swap($cookieParams, 'lifetime', 'expires');

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
        $started = $this->started;

        if (!$started || session_status() != PHP_SESSION_ACTIVE) {
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

            // If id is specified, it will replace the current session id, session_id() needs to be called
            // before session_start() for that purpose. @see http://php.net/manual/en/function.session-id.php
            if ($update) {
                session_id($this->id);
            }
            session_name($this->name);

            if (headers_sent($file, $line)) {
                throw new SessionException('Cannot use %s(), headers already sent at %s:%s',
                    [__method__, $file, $line]);
            }

            $started = session_start();
            if (!$started) {
                session_write_close();
                throw new SessionException('Session start failed');
            }

            if (session_id() !== $this->id) {
                session_write_close();
                throw new SessionException('Session ID match failed');
            }

            // Init sub-array.
            isset($_SESSION[$this->name]) || ($_SESSION[$this->name] = ['@' => $this->id]);
        }

        return ($this->started = (bool) $started);
    }

    /**
     * End.
     *
     * @param  bool $deleteCookie
     * @return bool
     */
    public function end(bool $deleteCookie = true): bool
    {
        $ended = $this->ended;

        if ($this->started && !$ended) {
            $ended = session_destroy();

            // Drop session cookie.
            $deleteCookie && setcookie($this->name(), '', $this->cookieParams());
        }

        return ($this->ended = (bool) $ended);
    }

    /**
     * Check id validity.
     *
     * @param  string|null $id
     * @return bool
     */
    public function isValidId(string|null $id): bool
    {
        $id = trim((string) $id);
        if ($id == '') {
            return false;
        }

        $saveHandler = $this->saveHandler();
        if ($saveHandler != null && method_exists($saveHandler, 'isValidId')) {
            return $saveHandler->isValidId($id);
        }

        static $idPattern; if ($idPattern == null) {
            if ($this->options['hash']) {
                $idPattern = sprintf(
                    '~^[A-F0-9]{%s}$~%s',
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
                if ($idBpc == '') {
                    ini_set('session.sid_length', $idLenDefault);
                    ini_set('session.sid_bits_per_character', ($idBpc = $idBpcDefault));
                }

                $idChars = '';
                switch ($idBpc) {
                    case '4': $idChars = '0-9a-f';      break;
                    case '5': $idChars = '0-9a-v';      break;
                    case '6': $idChars = '0-9a-zA-Z-,'; break;
                }

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
        if ($id == '') {
            return false;
        }

        $saveHandler = $this->saveHandler();
        if ($saveHandler != null && method_exists($saveHandler, 'isValidSource')) {
            return $saveHandler->isValidSource($id);
        }

        // For 'sess_' @see https://github.com/php/php-src/blob/master/ext/session/mod_files.c#L85
        return is_file(($this->savePath() ?? session_save_path()) .'/sess_'. $id);
    }

    /**
     * Generate id.
     *
     * @return string
     * @throws froq\session\SessionException
     */
    public function generateId(): string
    {
        $saveHandler = $this->saveHandler();
        if ($saveHandler != null && method_exists($saveHandler, 'generateId')) {
            return $saveHandler->generateId();
        }

        $id = session_create_id();

        // Hash by length.
        if ($this->options['hash']) {
            $algo = match ($this->options['hashLength']) {
                32 => 'md5', 40 => 'sha1', 16 => 'fnv1a64',
                default => throw new SessionException(
                    'Invalid `hashLength` option `%s`, valids are: 32,40,16',
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
        $form      = '@form:' . $form;
        $formToken = uuid_hash();

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
        $form      = '@form:' . $form;
        $formToken = $this->get($form);

        return $formToken && hash_equals($formToken, $token);
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
     * Put a var into session stack.
     *
     * @param  string|array<string, any> $key
     * @param  any|null                  $value
     * @return self
     * @throws froq\session\SessionException
     */
    public function set(string|array $key, $value = null): self
    {
        // Protect ID field.
        if ($key === '@') {
            throw new SessionException('Cannot modify `@` key in session data');
        }

        $name = $this->name();

        if (isset($_SESSION[$name])) {
            is_array($key)
                ? Arrays::setAll($_SESSION[$name], $key, $value)
                : Arrays::set($_SESSION[$name], $key, $value);
        }

        return $this;
    }

    /**
     * Get a var from session stack.
     *
     * @param  string|array<string> $key
     * @param  any|null             $default
     * @param  bool                 $drop
     * @return any|null
     */
    public function get(string|array $key, $default = null, bool $drop = false)
    {
        $name = $this->name();

        if (isset($_SESSION[$name])) {
            return is_array($key)
                 ? Arrays::getAll($_SESSION[$name], $key, $default, $drop)
                 : Arrays::get($_SESSION[$name], $key, $default, $drop);
        }

        return null;
    }

    /**
     * Remove a var from session stack.
     *
     * @param  string|array<string> $key
     * @return bool
     * @throws froq\session\SessionException
     */
    public function remove(string|array $key): bool
    {
        // Protect ID field.
        if ($key === '@') {
            throw new SessionException('Cannot remove `@` key in session data');
        }

        // No value assign or return, so just for dropping fields.
        return $this->get((array) $key, drop: true) !== null;
    }

    /**
     * Flash.
     *
     * @param  any|null $message
     * @return any|null
     */
    public function flash($message = null)
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
        foreach (array_keys($this->arrayify()) as $key) {
            if ($key !== '@') {
                $this->remove($key);
            }
        }
    }

    /**
     * @inheritDoc froq\common\interface\Arrayable
     */
    public function toArray(bool $deep = true): array
    {
        return Util::makeArray($this->arrayify(), $deep);
    }

    /**
     * @inheritDoc froq\common\interface\Objectable
     */
    public function toObject(bool $deep = true): object
    {
        return Util::makeObject($this->arrayify(), $deep);
    }

    /** @internal */
    private function arrayify(): array
    {
        return $_SESSION[$this->name()] ?? [];
    }
}
