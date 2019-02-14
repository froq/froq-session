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

use froq\util\traits\SingletonTrait;

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
     * Singleton trait.
     * @var froq\util\traits\SingletonTrait
     */
    use SingletonTrait;

    /**
     * Name.
     * @const string
     */
    public const NAME = 'SID';

    /**
     * Hash defaults.
     * @const any
     */
    public const HASH = true,
                 HASH_LENGTH = 40; // ID length (32, 40, 64, 128)

    /**
     * Cookie defaults.
     * @const any
     */
    public const COOKIE_LIFETIME = 0,
                 COOKIE_PATH = '/',
                 COOKIE_DOMAIN = '',
                 COOKIE_SECURE = false,
                 COOKIE_HTTPONLY = false,
                 COOKIE_SAMESITE = ''; // PHP/7.3

    /**
     * Sid defaults.
     * @const string
     */
    public const SID_LENGTH = '26',
                 SID_BITSPERCHARACTER = '5';

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
     * @var ?froq\session\SessionHandlerInterface
     */
    private $saveHandler;

    /**
     * Options.
     * @var array
     */
    private $options;

    /**
     * Cookie options.
     * @var array
     */
    private $cookieOptions;

    /**
     * Is started.
     * @var bool
     */
    private $isStarted = false;

    /**
     * Is ended.
     * @var bool
     */
    private $isEnded = false;

    /**
     * Constructor.
     * @param  array|null $options
     * @throws froq\session\SessionException
     */
    private function __construct(array $options = null)
    {
        $options = array_merge([
            'name' => self::NAME,
            'hash' => self::HASH, 'hashLength' => self::HASH_LENGTH,
            'savePath' => null, 'saveHandler' => null,
            'cookie' => [
                'lifetime' => self::COOKIE_LIFETIME, 'path' => self::COOKIE_PATH,
                'domain' => self::COOKIE_DOMAIN, 'secure' => self::COOKIE_SECURE,
                'httponly' => self::COOKIE_HTTPONLY, 'samesite' => self::COOKIE_SAMESITE,
            ]
        ], (array) $options);

        // save path
        if ($options['savePath'] != null) {
            $this->savePath = $options['savePath'];
            // check/make if option provided
            if (!is_dir($this->savePath)) {
                $ok = @mkdir($this->savePath, 0750, true);
                if (!$ok) {
                    throw new SessionException(sprintf('Cannot make directory, error[%s]',
                        error_get_last()['message'] ?? 'Unknown'));
                }
            }
        } else {
            $this->savePath = session_save_path();
        }
        session_save_path($this->savePath);

        // save handler
        if ($options['saveHandler'] != null) {
            $saveHandler = $options['saveHandler'];
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

            $this->saveHandler = new $saveHandler($this);
            if (!$this->saveHandler instanceof SessionHandlerInterface) {
                throw new SessionException("Handler must implement 'froq\session\SessionHandlerInterface' object");
            }

            // call init methods if exists
            if (method_exists($this->saveHandler, 'init')) {
                $this->saveHandler->init();
            }

            // set save handler
            session_set_save_handler($this->saveHandler, true);
        }

        // cookie options
        $cookieOptions = $options['cookie'] ?? session_get_cookie_params();
        $cookieOptions['lifetime'] = intval($cookieOptions['lifetime'] ?? self::COOKIE_LIFETIME);
        $cookieOptions['path'] = strval($cookieOptions['path'] ?? self::COOKIE_PATH);
        $cookieOptions['domain'] = strval($cookieOptions['domain'] ?? self::COOKIE_DOMAIN);
        $cookieOptions['secure'] = boolval($cookieOptions['secure'] ?? self::COOKIE_SECURE);
        $cookieOptions['httponly'] = boolval($cookieOptions['httponly'] ?? self::COOKIE_HTTPONLY);

        // set options
        $this->options = $options;
        $this->cookieOptions = $cookieOptions;

        // start
        if (!$this->isStarted || session_status() !== PHP_SESSION_ACTIVE) {
            // set cookie defaults
            session_set_cookie_params($cookieOptions['lifetime'], $cookieOptions['path'],
                $cookieOptions['domain'], $cookieOptions['secure'], $cookieOptions['httponly']);

            // @note If id is specified, it will replace the current session id. session_id() needs to be called
            // before session_start() for that purpose. @from http://php.net/manual/en/function.session-id.php
            $id = session_id();
            $idUpdate = false;
            $name = $options['name'] ?? self::NAME; // @default

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
                session_id($id);
            }
            session_name($name);

            $this->reset();
            $this->start();
        }
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
     * @return ?froq\session\SessionHandlerInterface
     */
    public function getSaveHandler(): ?SessionHandlerInterface
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
     * Get cookie options.
     * @return array
     */
    public function getCookieOptions(): array
    {
        return $this->cookieOptions;
    }

    /**
     * Is started.
     * @return bool
     */
    public function isStarted(): bool
    {
        return $this->isStarted;
    }

    /**
     * Is ended.
     * @return bool
     */
    public function isEnded(): bool
    {
        return $this->isEnded;
    }

    /**
     * Start.
     * @return bool
     * @throws froq\session\SessionException
     */
    public function start(): bool
    {
        if (!$this->isStarted) {
            // check headers
            if (headers_sent($file, $line)) {
                throw new SessionException(sprintf("Cannot use '%s()', headers already sent in %s:%s",
                    __method__, $file, $line));
            }

            // start session
            $this->isStarted = session_start();
            if (!$this->isStarted) {
                session_write_close();
                throw new SessionException(sprintf("Session start failed in '%s()'", __method__));
            }

            // check id for last time
            if (session_id() !== $this->id) {
                session_write_close();
                throw new SessionException(sprintf("Session ID match failed in '%s()'", __method__));
            }

            // init sub-array
            if (!isset($_SESSION[$this->name])) {
                $_SESSION[$this->name] = [];
            }
        }

        return $this->isStarted;
    }

    /**
     * End.
     * @param  bool $deleteCookie
     * @return bool
     */
    public function end(bool $deleteCookie = true): bool
    {
        if (!$this->isEnded) {
            $this->id = '';
            $this->isEnded = session_destroy();
            if ($this->isEnded) {
                $this->reset();
            }

            if ($deleteCookie) {
                setcookie($this->name, '', 0,
                    $this->cookieOptions['path'], $this->cookieOptions['domain'],
                    $this->cookieOptions['secure'], $this->cookieOptions['httponly']
                );
            }
        }

        return $this->isEnded;
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

        static $idPattern;
        if ($idPattern == null) {
            if ($this->options['hash']) {
                $idPattern = '~^[A-F0-9]{'. $this->options['hashLength'] .'}$~';
            } else {
                // @see http://php.net/manual/en/session.configuration.php#ini.session.sid-length
                // @see http://php.net/manual/en/session.configuration.php#ini.session.sid-bits-per-character
                // @see https://github.com/php/php-src/blob/PHP-7.1/UPGRADING#L114
                $idLength = ini_get('session.sid_length') ?: self::SID_LENGTH;
                $idBitsPerCharacter = ini_get('session.sid_bits_per_character');
                if ($idBitsPerCharacter == '') { // never happens, but obsession..
                    ini_set('session.sid_length', self::SID_LENGTH);
                    ini_set('session.sid_bits_per_character', ($idBitsPerCharacter = self::SID_BITSPERCHARACTER));
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

        // for 'sess_' @see https://github.com/php/php-src/blob/master/ext/session/mod_files.c#L85
        return file_exists($this->savePath .'/sess_'. $id);
    }

    /**
     * Generate id.
     * @return string
     * @throws froq\session\SessionException
     */
    public function generateId(): string
    {
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
     * @param  any          $value
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
     * @param  any          $valueDefault
     * @return any
     */
    public function get($key, $valueDefault = null)
    {
        if (is_array($key)) {
            $values = [];
            foreach ($key as $key) {
                $values[$key] = array_key_exists($key, $_SESSION[$this->name])
                    ? $_SESSION[$this->name][$key] : $valueDefault;
            }
            return $values;
        }

        return array_key_exists($key, $_SESSION[$this->name])
            ? $_SESSION[$this->name][$key] : $valueDefault;
    }

    /**
     * Remove.
     * @param  string|array $key
     * @return void
     */
    public function remove($key): void
    {
        foreach ((array) $key as $key) {
            unset($_SESSION[$this->name][$key]);
        }
    }

    /**
     * Flash.
     * @param  any $message
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
    private function reset(): void
    {
        $_SESSION[$this->name] = [];
    }
}
