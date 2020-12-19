<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\session;

use froq\session\{SessionException, AbstractHandler};
use froq\common\{interface\Arrayable, trait\OptionTrait};
use froq\util\Arrays;

/**
 * Session.
 * @package froq\session
 * @object  froq\session\Session
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 */
final class Session implements Arrayable
{
    /**
     * @see froq\common\trait\OptionTrait
     * @since 4.0
     */
    use OptionTrait;

    /**
     * Id.
     * @var ?string
     */
    private ?string $id;

    /**
     * Name.
     * @var ?string
     */
    private ?string $name;

    /**
     * Save path.
     * @var ?string
     */
    private ?string $savePath;

    /**
     * Save handler.
     * @var ?object
     */
    private ?object $saveHandler;

    /**
     * Started.
     * @var ?bool
     */
    private ?bool $started;

    /**
     * Ended.
     * @var ?bool
     */
    private ?bool $ended;

    /**
     * Options default.
     * @var array
     */
    private static array $optionsDefault = [
        'name'     => 'SID',
        'hash'     => true, 'hashLength'  => 32, 'hashUpper' => true,
        'savePath' => null, 'saveHandler' => null,
        'cookie'   => [
            'lifetime' => 0,     'path'     => '/',   'domain'   => '',
            'secure'   => false, 'httponly' => false, 'samesite' => '',
        ]
    ];

    /**
     * Constructor.
     * @param  array<string, any>|null $options
     * @throws froq\session\SessionException
     */
    public function __construct(array $options = null)
    {
        $options = array_merge(self::$optionsDefault, $options ?? []);
        $options['cookie'] = array_merge(self::$optionsDefault['cookie'], array_change_key_case(
            (array) ($options['cookie'] ?? []), CASE_LOWER
        ));

        $this->setOptions($options);

        $savePath = $options['savePath'];
        if ($savePath != null) {
            if (!is_dir($savePath)) {
                $ok = mkdir($savePath, 0755, true);
                if (!$ok) {
                    throw new SessionException('Cannot make directory for `savePath` option [error: %s]',
                        '@error');
                }
            }
            session_save_path($savePath);

            $this->savePath = $savePath;
        }

        $saveHandler = $options['saveHandler'];
        if ($saveHandler != null) {
            if (is_array($saveHandler)) { // File given?
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

            if (!class_exists($saveHandler)) {
                throw new SessionException('Handler class `%s` not found', $saveHandler);
            }
            if (!class_extends($saveHandler, AbstractHandler::class)) {
                throw new SessionException('Handler class must extend `%s` class', AbstractHandler::class);
            }

            // Init handler.
            $saveHandler = new $saveHandler($this);

            session_set_save_handler($saveHandler);

            $this->saveHandler = $saveHandler;
        }

        // Set cookie defaults.
        session_set_cookie_params($options['cookie'] ?? session_get_cookie_params());
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
     * @return ?string
     */
    public function getId(): ?string
    {
        return $this->id ?? null;
    }

    /**
     * Get name.
     * @return ?string
     */
    public function getName(): ?string
    {
        return $this->name ?? null;
    }

    /**
     * Get save path.
     * @return ?string
     */
    public function getSavePath(): ?string
    {
        return $this->savePath ?? null;
    }

    /**
     * Get save handler.
     * @return ?object
     */
    public function getSaveHandler(): ?object
    {
        return $this->saveHandler ?? null;
    }

    /**
     * Get cookie.
     * @return array
     * @since  4.1
     */
    public function getCookie(): array
    {
        $name  = $this->getName();
        $value = $_COOKIE[$name] ?? null;

        return [$name, $value];
    }

    /**
     * Get cookie params.
     * @param  bool $swap
     * @return array
     * @since  4.1
     */
    public function getCookieParams(bool $swap = true): array
    {
        $cookieParams = session_get_cookie_params();

        // Fix: "Unrecognized key 'lifetime' found".
        $swap && Arrays::swap($cookieParams, 'lifetime', 'expires');

        return $cookieParams;
    }

    /**
     * Is started.
     * @return ?bool
     */
    public function isStarted(): ?bool
    {
        return $this->started ?? null;
    }

    /**
     * Is ended.
     * @return ?bool
     */
    public function isEnded(): ?bool
    {
        return $this->ended ?? null;
    }

    /**
     * Start.
     * @return bool
     * @throws froq\session\SessionException
     */
    public function start(): bool
    {
        $started = $this->isStarted();

        if (!$started || session_status() != PHP_SESSION_ACTIVE) {
            $id       = session_id();
            $idUpdate = false;
            $name     = $this->options['name'];

            if ($this->isValidId($id)) {
                // Pass, never happens, but obsession..
            } else {
                // Hard and hard.
                $id = $_COOKIE[$name] ?? '';
                if (!$this->isValidId($id) || !$this->isValidSource($id)) {
                    $id = $this->generateId();
                    $idUpdate = true;
                }
            }

            // Set id & name.
            $this->id   = $id;
            $this->name = $name;

            if ($idUpdate) {
                // @note: If id is specified, it will replace the current session id, session_id() needs to be called
                // before session_start() for that purpose. @see http://php.net/manual/en/function.session-id.php
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
            if (!isset($_SESSION[$this->name])) {
                $_SESSION[$this->name] = ['@' => $this->id];
            }
        }

        return (bool) ($this->started = $started);
    }

    /**
     * End.
     * @param  bool $deleteCookie
     * @return bool
     */
    public function end(bool $deleteCookie = true): bool
    {
        $started = $this->isStarted();
        $ended   = $this->isEnded();

        if ($started && !$ended) {
            $ended = session_destroy();

            if ($deleteCookie) {
                setcookie($this->getName(), '', $this->getCookieParams());
            }
        }

        return (bool) ($this->ended = $ended);
    }

    /**
     * Is valid id.
     * @param  ?string $id
     * @return bool
     */
    public function isValidId(?string $id): bool
    {
        if ($id == '') {
            return false;
        }

        $saveHandler = $this->getSaveHandler();
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
                $idBitsPerCharDefault = '5';

                $idLen = ini_get('session.sid_length') ?: $idLenDefault;
                $idBitsPerChar = ini_get('session.sid_bits_per_character');
                if ($idBitsPerChar == '') {
                    ini_set('session.sid_length', $idLenDefault);
                    ini_set('session.sid_bits_per_character', ($idBitsPerChar = $idBitsPerCharDefault));
                }

                $idChars = '';
                switch ($idBitsPerChar) {
                    case '4': $idChars = '0-9a-f'; break;
                    case '5': $idChars = '0-9a-v'; break;
                    case '6': $idChars = '0-9a-zA-Z-,'; break;
                }

                $idPattern = '~^[' . $idChars . ']{' . $idLen . '}$~';
            }
        }

        return (bool) preg_match($idPattern, $id);
    }

    /**
     * Is valid source.
     * @param  ?string $id
     * @return bool
     */
    public function isValidSource(?string $id): bool
    {
        if ($id == '') {
            return false;
        }

        $saveHandler = $this->getSaveHandler();
        if ($saveHandler != null && method_exists($saveHandler, 'isValidSource')) {
            return $saveHandler->isValidSource($id);
        }

        // For 'sess_' @see https://github.com/php/php-src/blob/master/ext/session/mod_files.c#L85
        return is_file(($this->getSavePath() ?? session_save_path()) .'/sess_'. $id);
    }

    /**
     * Generate id.
     * @return string
     * @throws froq\session\SessionException
     */
    public function generateId(): string
    {
        $saveHandler = $this->getSaveHandler();
        if ($saveHandler != null && method_exists($saveHandler, 'generateId')) {
            return $saveHandler->generateId();
        }

        $id = session_create_id();

        // Hash by length.
        if ($this->options['hash']) {
            switch ($this->options['hashLength']) {
                case 16: $id = hash('fnv1a64', $id); break;
                case 32: $id = hash('md5', $id);     break;
                case 40: $id = hash('sha1', $id);    break;
                default:
                    throw new SessionException('Invalid `hashLength` option `%s`, valids are: 16, 32, 40',
                        $this->options['hashLength']);
            }

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
        $formToken = md5(uniqid() . random_bytes(16));

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

        return $token && $formToken && hash_equals($token, $formToken);
    }

    /**
     * Has.
     * @param  string $key
     * @return bool
     */
    public function has(string $key): bool
    {
        $name = $this->getName();

        return isset($_SESSION[$name][$key]);
    }

    /**
     * Set.
     * @param  string|array<string, any> $key
     * @param  any|null                  $value
     * @return self
     */
    public function set($key, $value = null): self
    {
        // Protect ID field.
        if ($key === '@') {
            throw new SessionException('Cannot modify `@` key in session data');
        }

        $name = $this->getName();

        if (isset($_SESSION[$name])) {
            if (is_array($key)) {
                foreach ($key as $key => $value) {
                    $_SESSION[$name][$key] = $value;
                }
            } else {
                $_SESSION[$name][$key] = $value;
            }
        }

        return $this;
    }

    /**
     * Get.
     * @param  string|array<string, any> $key
     * @param  any|null                  $default
     * @param  bool                      $remove
     * @return any
     */
    public function get($key, $default = null, bool $remove = false)
    {
        $name = $this->getName();

        if (isset($_SESSION[$name])) {
            return is_array($key)
                 ? Arrays::getAll($_SESSION[$name], $key, $default, $remove)
                 : Arrays::get($_SESSION[$name], $key, $default, $remove);
        }

        return null;
    }

    /**
     * Remove.
     * @param  string|array<string, any> $key
     * @return void
     */
    public function remove($key): void
    {
        // Protect ID field.
        if ($key === '@') {
            throw new SessionException('Cannot remove `@` key in session data');
        }

        // No value assign or return, so just for dropping fields with "true".
        $this->get((array) $key, remove: true);
    }

    /**
     * Flash.
     * @param  any|null $message
     * @return any|null
     */
    public function flash($message = null)
    {
        return func_num_args()
             ? $this->set('@flash', $message)
             : $this->get('@flash', null, true);
    }

    /**
     * Flush.
     * @return void
     * @since 4.2
     */
    public function flush(): void
    {
        foreach (array_keys($this->toArray()) as $key) {
            ($key !== '@') && $this->remove($key);
        }
    }

    /**
     * @inheritDoc froq\common\interface\Arrayable
     */
    public function toArray(): array
    {
        $name = $this->getName();

        $ret = [];
        if (isset($_SESSION[$name])) {
            $ret = $_SESSION[$name];
        }
        return $ret;
    }
}
