<?php
/**
 * MIT License <https://opensource.org/licenses/mit>
 *
 * Copyright (c) 2015 Kerem Güneş
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
declare(strict_types=1);

namespace froq\session;

use froq\util\Arrays;

/**
 * Session.
 * @package froq\session
 * @object  froq\session\Session
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 */
final class Session
{
    /**
     * Id.
     * @var string
     */
    private $id;

    /**
     * name.
     * @var string
     */
    private $name;

    /**
     * Save path.
     * @var string
     */
    private $savePath;

    /**
     * Save handler.
     * @var ?object
     */
    private $saveHandler;

    /**
     * Options.
     * @var array
     */
    private $options = [];

    /**
     * Options default.
     * @var array
     */
    private static $optionsDefault = [
        'name'     => 'SID',
        'hash'     => true, 'hashLength' => 32, // ID length (32, 40, 64, 128)
        'savePath' => null, 'saveHandler' => null,
        'cookie'   => [
            'lifetime' => 0,     'path' => '/',
            'domain'   => '',    'secure' => false,
            'httponly' => false, /* 'samesite' => '', // PHP/7.3 */
        ]
    ];

    /**
     * Started.
     * @var bool
     */
    private $started = false;

    /**
     * Ended.
     * @var bool
     */
    private $ended = false;

    /**
     * Constructor.
     * @param  array|null $options
     * @throws froq\session\SessionException
     */
    public function __construct(array $options = null)
    {
        $this->options = array_merge(self::$optionsDefault, (array) ($options ?? []));
        $this->options['cookie'] = array_merge(self::$optionsDefault['cookie'], (array) ($options['cookie'] ?? []));

        $savePath = $this->options['savePath'];
        if ($savePath != null) {
            if (!is_dir($savePath)) {
                $ok =@ mkdir($savePath, 0750, true);
                if (!$ok) {
                    throw new SessionException(sprintf('Cannot make directory, error[%s]',
                        error_get_last()['message'] ?? 'Unknown'));
                }
            }
            session_save_path($savePath);

            $this->savePath = $savePath;
        }

        $saveHandler = $this->options['saveHandler'];
        if ($saveHandler != null) {
            if (is_array($saveHandler)) { // file given
                @ [$saveHandler, $saveHandlerFile] = $saveHandler;
                if (!isset($saveHandler, $saveHandlerFile)) {
                    throw new SessionException("Both handler and handler file are required");
                }
                if (!file_exists($saveHandlerFile)) {
                    throw new SessionException("Could not find given handler file '{$saveHandlerFile}'");
                }
                require_once $saveHandlerFile;
            }

            if (!class_exists($saveHandler, true)) {
                throw new SessionException("Handler class '{$saveHandler}' not found");
            }
            if (!is_subclass_of($saveHandler, 'froq\\session\\SessionHandler', true)) {
                throw new SessionException("Handler class must extend 'froq\\session\\SessionHandler' object");
            }

            // init handler & call init method if exists ('cos handler constructor is final)
            $saveHandler = new $saveHandler($this);
            if (method_exists($saveHandler, 'init')) {
                $saveHandler->init();
            }
            session_set_save_handler($saveHandler, true);

            $this->saveHandler = $saveHandler;
        }

        // set cookie defaults
        $cookieParams = $this->options['cookie'] ?? session_get_cookie_params();
        session_set_cookie_params(
            $cookieParams['lifetime'] ?? self::$optionsDefault['lifetime'],
            $cookieParams['path'] ?? self::$optionsDefault['path'],
            $cookieParams['domain'] ?? self::$optionsDefault['domain'],
            $cookieParams['secure'] ?? self::$optionsDefault['secure'],
            $cookieParams['httponly'] ?? self::$optionsDefault['httponly']
        );
    }

    /**
     * Destructor.
     * @return void
     */
    public function __destruct()
    {
        session_register_shutdown();
    }

    /**
     * Get id.
     * @return string
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * Get name.
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Get save path.
     * @return string
     */
    public function getSavePath(): string
    {
        return $this->savePath;
    }

    /**
     * Get save handler.
     * @return ?object
     */
    public function getSaveHandler(): ?object
    {
        return $this->saveHandler;
    }

    /**
     * Get options.
     * @return array
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Get option.
     * @param  string $key
     * @return any|null
     */
    public function getOption(string $key)
    {
        return $this->options[$key] ?? null;
    }

    /**
     * Is started.
     * @return bool
     */
    public function isStarted(): bool
    {
        return $this->started;
    }

    /**
     * Is ended.
     * @return bool
     */
    public function isEnded(): bool
    {
        return $this->ended;
    }

    /**
     * Start.
     * @return bool
     * @throws froq\session\SessionException
     */
    public function start(): bool
    {
        if (!$this->started || session_status() !== PHP_SESSION_ACTIVE) {
            $id = session_id();
            $idUpdate = false;
            $name = $this->options['name'];

            if ($this->isValidId($id)) { // never happens, but obsession..
                // ok
            } else {
                // hard and hard..
                $id = $_COOKIE[$name] ?? '';
                if (!$this->isValidId($id) || !$this->isValidSource($id)) {
                    $id = $this->generateId();
                    $idUpdate = true;
                }
            }

            // set id & name
            $this->id = $id;
            $this->name = $name;
            if ($idUpdate) {
                // @note If id is specified, it will replace the current session id. session_id() needs to be called
                // before session_start() for that purpose. @from http://php.net/manual/en/function.session-id.php
                session_id($this->id);
            }
            session_name($this->name);

            if (headers_sent($file, $line)) {
                throw new SessionException(sprintf("Cannot use '%s()', headers already sent in %s:%s",
                    __method__, $file, $line));
            }

            $this->started = session_start();
            if (!$this->started) {
                session_write_close();
                throw new SessionException(sprintf("Session start failed in '%s()'", __method__));
            }

            if (session_id() !== $this->id) {
                session_write_close();
                throw new SessionException(sprintf("Session ID match failed in '%s()'", __method__));
            }

            // init sub-array
            if (!isset($_SESSION[$this->name])) {
                $_SESSION[$this->name] = ['@' => $this->id];
            }
        }

        return $this->started;
    }

    /**
     * End.
     * @param  bool $deleteCookie
     * @return bool
     */
    public function end(bool $deleteCookie = true): bool
    {
        if (!$this->ended) {
            $this->id = '';
            $this->ended = session_destroy();
            if ($this->ended) {
                $this->reset();
            }

            if ($deleteCookie) {
                $cookieParams = session_get_cookie_params();
                setcookie($this->name, '', 0, $cookieParams['path'], $cookieParams['domain'],
                    $cookieParams['secure'], $cookieParams['httponly']);
            }
        }

        return $this->ended;
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

        if ($this->saveHandler != null && method_exists($this->saveHandler, 'isValidId')) {
            return $this->saveHandler->isValidId($id);
        }

        static $idPattern; if ($idPattern == null) {
            if ($this->options['hash']) {
                $idPattern = '~^[A-F0-9]{'. $this->options['hashLength'] .'}$~';
            } else {
                // @see http://php.net/manual/en/session.configuration.php#ini.session.sid-length
                // @see http://php.net/manual/en/session.configuration.php#ini.session.sid-bits-per-character
                // @see https://github.com/php/php-src/blob/PHP-7.1/UPGRADING#L114
                $defaultSidLength = '26'; $defaultSidBitsPerCharacter = '5';
                $idLength = ini_get('session.sid_length') ?: $defaultSidLength;
                $idBitsPerCharacter = ini_get('session.sid_bits_per_character');
                if ($idBitsPerCharacter == '') { // never happens, but obsession..
                    ini_set('session.sid_length', $defaultSidLength);
                    ini_set('session.sid_bits_per_character', ($idBitsPerCharacter = $defaultSidBitsPerCharacter));
                }

                $idCharacters = '';
                switch ($idBitsPerCharacter) {
                    case '4': $idCharacters = '0-9a-f'; break;
                    case '5': $idCharacters = '0-9a-v'; break;
                    case '6': $idCharacters = '0-9a-zA-Z-,'; break;
                }

                $idPattern = '~^['. $idCharacters .']{'. $idLength .'}$~';
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

        if ($this->saveHandler != null && method_exists($this->saveHandler, 'isValidSource')) {
            return $this->saveHandler->isValidSource($id);
        }

        // @see: 'sess_' => https://github.com/php/php-src/blob/master/ext/session/mod_files.c#L85
        return file_exists(($this->savePath ?? session_save_path()) .'/sess_'. $id);
    }

    /**
     * Generate id.
     * @return string
     * @throws froq\session\SessionException
     */
    public function generateId(): string
    {
        if ($this->saveHandler != null && method_exists($this->saveHandler, 'generateId')) {
            return $this->saveHandler->generateId();
        }

        $id = session_create_id();

        // hash by length
        if ($this->options['hash']) {
            switch ($this->options['hashLength']) {
                case 32: $id = hash('md5', $id); break;
                case 40: $id = hash('sha1', $id); break;
                case 64: $id = hash('sha256', $id); break;
                case 128: $id = hash('sha512', $id); break;
                default:
                    throw new SessionException("No valid 'hashLength' option given, only ".
                        "'32,40,64,128' are accepted");
            }
            $id = strtoupper($id);
        }

        return $id;
    }

    /**
     * Has.
     * @param  string $key
     * @return bool
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $_SESSION[$this->name]);
    }

    /**
     * Set.
     * @param  string|array $key
     * @param  any|null     $value
     * @return self
     */
    public function set($key, $value = null): self
    {
        if (is_array($key)) {
            // must be assoc array
            foreach ($key as $key => $value) {
                $_SESSION[$this->name][$key] = $value;
            }
        } else {
            $_SESSION[$this->name][$key] = $value;
        }

        return $this;
    }

    /**
     * Get.
     * @param  string|array $key
     * @param  any|null     $valueDefault
     * @param  bool         $remove
     * @return any
     */
    public function get($key, $valueDefault = null, bool $remove = false)
    {
        $ret = Arrays::get($_SESSION[$this->name], $key, $valueDefault);
        if ($remove && $ret !== null) {
            $this->remove($key);
        }
        return $ret;
    }

    /**
     * Remove.
     * @param  string|array $key
     * @return void
     */
    public function remove($key): void
    {
        $keys = (array) $key;
        foreach ($keys as $key) {
            unset($_SESSION[$this->name][$key]);
        }
    }

    /**
     * Flash.
     * @param  any|null $message
     * @return any
     */
    public function flash($message = null)
    {
        // set
        if ($message !== null) {
            $this->set('@flash', $message);
        } else { // get
            $message = $this->get('@flash');
            $this->remove('@flash');
            return $message;
        }
    }

    /**
     * To array.
     * @return array
     */
    public function toArray(): array
    {
        $array = [];
        if (isset($_SESSION[$this->name])) {
            $array = to_array($_SESSION[$this->name], true);
        }

        return $array;
    }

    /**
     * Reset.
     * @return void
     */
    public function reset(): void
    {
        unset($_SESSION[$this->name]);
    }
}
