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

namespace Froq\Session;

use Froq\Util\Traits\SingleTrait;

/**
 * @package    Froq
 * @subpackage Froq\Session
 * @object     Froq\Session\Session
 * @author     Kerem Güneş <k-gun@mail.com>
 */
final class Session
{
    /**
     * Single.
     * @var Froq\Util\Traits\SingleTrait
     */
    use SingleTrait;

    /**
     * Name.
     * @const string
     */
    const NAME = 'SID';

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
     * @var ?Froq\Session\SessionHandlerInterface
     */
    private $saveHandler;

    /**
     * Options.
     * @var array
     */
    private $options = [
        'name'     => 'SID',
        'hash'     => true, 'hashLength'  => 40, // ID length (32, 40, 64, 128)
        'savePath' => null, 'saveHandler' => null,
        'cookie'   => [
            'lifetime' => 0,     'path'     => '/',   'domain'   => '',
            'secure'   => false, 'httponly' => false, 'samesite' => '', // PHP/7.3
        ]
    ];

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
     * Is destroyed.
     * @var bool
     */
    private $isDestroyed = false;

    /**
     * Constructor.
     * @param  array|null $options
     * @throws Froq\Session\SessionException
     */
    private function __construct(array $options = null)
    {
        if ($options != null) {
            $this->options = array_merge($this->options, $options);
        }

        // save path
        $this->savePath = $this->options['savePath'] ?? session_save_path();
        session_save_path($this->savePath);

        // save handler
        if ($this->options['saveHandler'] != null) {
            $saveHandler = $this->options['saveHandler'];
            if (is_array($saveHandler)) { // file given
                @ [$saveHandler, $saveHandlerFile] = $saveHandler;
                if (!isset($saveHandler, $saveHandlerFile)) {
                    throw new SessionException("Both handler and handler file are required!");
                }
                if (!file_exists($saveHandlerFile)) {
                    throw new SessionException("Could not find given handler file '{$saveHandlerFile}'!");
                }
                require_once $saveHandlerFile;
            }

            if (!class_exists($saveHandler, true)) {
                throw new SessionException("Handler class '{$saveHandler}' not found!");
            }

            $this->saveHandler = new $saveHandler($this);
            if (!$this->saveHandler instanceof SessionHandlerInterface) {
                throw new SessionException("Handler must implement 'Froq\Session\SessionHandlerInterface' object");
            }

            // call init methods if exists
            if (method_exists($this->saveHandler, 'init')) {
                $this->saveHandler->init();
            }

            // set save handler
            session_set_save_handler($this->saveHandler, true);
        }

        // cookie options
        $this->cookieOptions = $this->options['cookie'] ?? session_get_cookie_params();
        $this->cookieOptions['lifetime'] = (int) ($this->cookieOptions['lifetime'] ?? 0);
        $this->cookieOptions['path'] = (string) ($this->cookieOptions['path'] ?? '/');
        $this->cookieOptions['domain'] = (string) ($this->cookieOptions['domain'] ?? '');
        $this->cookieOptions['secure'] = (bool) ($this->cookieOptions['secure'] ?? false);
        $this->cookieOptions['httponly'] = (bool) ($this->cookieOptions['httponly'] ?? false);


        // start
        if (!$this->isStarted || session_status() !== PHP_SESSION_ACTIVE) {
            // set cookie defaults
            session_set_cookie_params(
                $this->cookieOptions['lifetime'],
                $this->cookieOptions['path'], $this->cookieOptions['domain'],
                $this->cookieOptions['secure'], $this->cookieOptions['httponly']
            );

            // @note If id is specified, it will replace the current session id. session_id() needs to be called
            // before session_start() for that purpose. @from http://php.net/manual/en/function.session-id.php
            $id = session_id();
            $name = $this->options['name'] ?? self::NAME; // @default

            if ($this->isValidId($id)) { // never happens, but obsession..
                // ok
            } else {
                // hard and hard..
                $id = $_COOKIE[$name] ?? '';
                if (!$this->isValidId($id) || !$this->isValidSource($id)) {
                    $id = $this->generateId();
                }
            }

            // set id & name
            $this->setId($id);
            $this->setName($name);

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
     * Set magic.
     * @param  string $key
     * @param  any    $value
     * @return void
     * @throws Froq\Session\SessionException
     */
    public function __set(string $key, $value)
    {
        if (!isset($_SESSION[$this->name])) {
            session_abort();
            throw new SessionException(sprintf(
                "Session not started yet, call first '%s::start()' or use isset() first!", __class__));
        }

        $_SESSION[$this->name][$key] = $value;
    }

    /**
     * Get magic.
     * @param  string $key
     * @return any
     * @throws Froq\Session\SessionException
     */
    public function __get(string $key)
    {
        if (!isset($_SESSION[$this->name])) {
            session_abort();
            throw new SessionException(sprintf(
                "Session not started yet, call first '%s::start()' or use isset() first!", __class__));
        }

        return array_key_exists($key, $_SESSION[$this->name]) ? $_SESSION[$this->name][$key] : null;
    }

    /**
     * Isset magic.
     * @param  string $key
     * @return bool
     * @throws Froq\Session\SessionException
     */
    public function __isset(string $key)
    {
        if (!isset($_SESSION[$this->name])) {
            session_abort();
            throw new SessionException(sprintf(
                "Session not started yet, call first '%s::start()' or use isset() first!", __class__));
        }

        return array_key_exists($key, $_SESSION[$this->name]);
    }

    /**
     * Unset magic.
     * @param  string $key
     * @return void
     * @throws Froq\Session\SessionException
     */
    public function __unset(string $key)
    {
        if (!isset($_SESSION[$this->name])) {
            session_abort();
            throw new SessionException(sprintf(
                "Session not started yet, call first '%s::start()' or use isset() first!", __class__));
        }

        unset($_SESSION[$this->name][$key]);
    }

    /**
     * Has.
     * @param  string $key
     * @return bool
     */
    public function has(string $key): bool
    {
        return $this->__isset($key);
    }

    /**
     * Set.
     * @param  string $key
     * @param  any    $value
     * @return void
     */
    public function set(string $key, $value): void
    {
        $this->__set($key, $value);
    }

    /**
     * Set all.
     * @param  array $data
     * @return void
     */
    public function setAll(array $data): void
    {
        foreach ($data as $key => $value) {
            $this->__set($key, $value);
        }
    }

    /**
     * Get.
     * @param  string $key
     * @param  any    $valueDefault
     * @return any
     */
    public function get(string $key, $valueDefault = null)
    {
        return (null !== ($value = $this->__get($key))) ? $value : $valueDefault;
    }

    /**
     * Get all.
     * @param  array $keys
     * @return array
     */
    public function getAll(array $keys): array
    {
        $data = [];
        foreach ($keys as $key) {
            $data[$keys] = $this->__get($key);
        }

        return $data;
    }

    /**
     * Remove.
     * @param  string $key
     * @return void
     */
    public function remove(string $key): void
    {
        $this->__unset($key);
    }

    /**
     * Remove all.
     * @param  array $keys
     * @return void
     */
    public function removeAll(array $keys): void
    {
        foreach ($keys as $key) {
            $this->__unset($key);
        }
    }

    /**
     * Set id.
     * @param  string $id
     * @return void
     */
    public function setId(string $id): void
    {
        $this->id = $id;

        session_id($id); // update
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
     * Set name.
     * @param  string $name
     * @return void
     */
    public function setName(string $name): void
    {
        $this->name = $name;

        session_name($name); // update
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
     * Get save handler.
     * @return ?Froq\Session\SessionHandlerInterface
     */
    public function getSaveHandler(): ?SessionHandlerInterface
    {
        return $this->saveHandler;
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
     * Is destroyed.
     * @return bool
     */
    public function isDestroyed(): bool
    {
        return $this->isDestroyed;
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
                $idLength = ini_get('session.sid_length') ?: '26';
                $idBitsPerCharacter = ini_get('session.sid_bits_per_character');
                if ($idBitsPerCharacter == '') { // never happens, but obsession..
                    ini_set('session.sid_length', '26');
                    ini_set('session.sid_bits_per_character', ($idBitsPerCharacter = '5'));
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

        // @see https://github.com/php/php-src/blob/master/ext/session/mod_files.c#L85
        return file_exists($this->savePath .'/sess_'. $id);
    }

    /**
     * Start.
     * @return bool
     * @throws Froq\Session\SessionException
     */
    public function start(): bool
    {
        if (!$this->isStarted) {
            // check headers
            if (headers_sent($file, $line)) {
                throw new SessionException(sprintf(
                    "Call '%s()' before outputs have been sent. [output location: '%s:%s']",
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
     * Destroy.
     * @param  bool $deleteCookie
     * @return bool
     */
    public function destroy(bool $deleteCookie = true): bool
    {
        $this->id = null;

        if (!$this->isDestroyed) {
            $this->isDestroyed = session_destroy();
            if ($this->isDestroyed) {
                $this->reset();
            }
            if ($deleteCookie) {
                $this->deleteCookie();
            }
        }

        return $this->isDestroyed;
    }

    /**
     * Delete cookie.
     * @return void
     */
    public function deleteCookie(): void
    {
        if (isset($_COOKIE[$this->name])) {
            setcookie($this->name, '', 0,
                $this->cookieOptions['path'], $this->cookieOptions['domain'],
                $this->cookieOptions['secure'], $this->cookieOptions['httponly']
            );
        }
    }

    /**
     * Generate id.
     * @return string
     * @throws Froq\Session\SessionException
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
                        "'32,40,64,128' are accepted!");
            }
            $id = strtoupper($id);
        }

        return $id;
    }

    /**
     * Regenerate id.
     * @param  bool $deleteOldSession
     * @return bool
     * @throws Froq\Session\SessionException
     */
    public function regenerateId(bool $deleteOldSession = true): bool
    {
        // check headers sent?
        if (headers_sent($file, $line)) {
            throw new SessionException(sprintf(
                "Call to '%s()' after outputs have been sent. [output location is '%s:%s']",
                    __method__, $file, $line));
        }

        $return = session_regenerate_id($deleteOldSession);

        // set/store id
        $this->setId($this->generateId());

        return $return;
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
