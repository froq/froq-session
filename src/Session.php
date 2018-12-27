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
     * Handler.
     * @var object
     */
    private $handler;

    /**
     * Options.
     * @var array
     */
    private $options = [
        'name'            => 'SID',
        'domain'          => '',
        'path'            => '/',
        'secure'          => false,
        'httponly'        => false,
        'lifetime'        => 0,
        'length'          => 32, // ID length (32, 40, 64, 128)
        'handler'         => null // object name for session_set_save_handler()
    ];

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
     * Save path.
     * @var string
     */
    private $savePath;

    /**
     * Constructor.
     * @param  array|null $options
     * @throws Froq\Session\SessionException
     */
    private function __construct(array $options = null)
    {
        // merge options
        if ($options != null) {
            $this->options = array_merge($this->options, $options);
        }

        $this->name = $this->options['name'];

        // handler
        if (isset($this->options['handler'])) {
            $handler = $this->options['handler'];
            if (is_array($handler)) { // file given
                @ [$handler, $handlerFile] = $handler;
                if (!isset($handler, $handlerFile)) {
                    throw new SessionException("Both handler and handler file are required!");
                }

                if (!file_exists($handlerFile)) {
                    throw new SessionException("Could not find given handler file '{$handlerFile}'!");
                }

                require_once $handlerFile;
            }

            if (!class_exists($handler, true)) {
                throw new SessionException("Handler class '{$handler}' not found!");
            }

            $this->handler = new $handler($this);
            if (!$this->handler instanceof SessionHandlerInterface) {
                throw new SessionException("Handler must implement 'Froq\Session\SessionHandlerInterface' object");
            }

            // call init methods if exists
            if (method_exists($this->handler, 'init')) {
                $this->handler->init();
            }

            // set handler
            session_set_save_handler($this->handler, true);
        }

        $this->savePath = session_save_path();

        // session is active?
        if (!$this->isStarted || session_status() !== PHP_SESSION_ACTIVE) {
            // set defaults
            session_set_cookie_params(
                (int)    $this->options['lifetime'],
                (string) $this->options['path'],
                (string) $this->options['domain'],
                (bool)   $this->options['secure'],
                (bool)   $this->options['httponly']
            );

            // set session name
            session_name($this->name);

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
     * Set.
     * @param  string $key
     * @param  any    $value
     * @return self
     */
    public function set(string $key, $value): self
    {
        $this->__set($key, $value);

        return $this;
    }

    /**
     * Set all.
     * @param  array $data
     * @return self
     */
    public function setAll(array $data): self
    {
        foreach ($data as $key => $value) {
            $this->__set($key, $value);
        }

        return $this;
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
     * @return self
     */
    public function remove(string $key): self
    {
        $this->__unset($key);

        return $this;
    }

    /**
     * Remove all.
     * @param  array $keys
     * @return self
     */
    public function removeAll(array $keys): self
    {
        foreach ($keys as $key) {
            $this->__unset($key);
        }

        return $this;
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
     * @return ?string
     */
    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * Get name.
     * @return ?string
     */
    public function getName(): ?string
    {
        return $this->name;
    }

    /**
     * Get handler.
     * @return Froq\Session\SessionHandlerInterface
     */
    public function getHandler(): ?SessionHandlerInterface
    {
        return $this->handler;
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
     * Get save path.
     * @return string
     */
    public function getSavePath(): string
    {
        return $this->savePath;
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
     * @param  string $id
     * @return bool
     */
    public function isValidId(string $id): bool
    {
        if ($this->handler != null && method_exists($this->handler, 'isValidId')) {
            return $this->handler->isValidId($id);
        }

        return !!($id && preg_match('~^[A-F0-9]{'. $this->options['length'] .'}$~', $id));
    }

    /**
     * Is valid source.
     * @param  string $id
     * @return bool
     */
    public function isValidSource(string $id): bool
    {
        if ($this->handler != null && method_exists($this->handler, 'isValidSource')) {
            return $this->handler->isValidSource($id);
        }

        // sess_: https://github.com/php/php-src/blob/master/ext/session/mod_files.c#L85
        return !!($id && file_exists($this->savePath .'/sess_'. $id));
    }

    /**
     * Start.
     * @return bool
     * @throws Froq\Session\SessionException
     */
    public function start(): bool
    {
        if ($this->isStarted) {
            // check headers
            if (headers_sent($file, $line)) {
                throw new SessionException(sprintf(
                    "Call '%s()' before outputs have been sent. [output location: '%s:%s']", __method__, $file, $line));
            }

            // check & set id
            $id = session_id();
            if ($this->isValidId($id)) {
                $this->setId($id);
            } else {
                $id = trim($_COOKIE[$this->name] ?? '');
                // hard and hard..
                if ($this->isValidId($id) && $this->isValidSource($id)) {
                    $this->setId($id);
                } else {
                    $this->setId($this->generateId());
                }
            }

            // start session
            $this->isStarted = session_start();
            if (!$this->isStarted) {
                session_write_close();
                throw new SessionException(sprintf("Session start is failed in '%s()'", __method__));
            }

            // check id
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
            $params = session_get_cookie_params();
            setcookie($this->name, '', 0, $params['path'], $params['domain'], $params['secure'],
                $params['httponly']);
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
        switch ($this->options['length']) {
            case 32: $id = hash('md5', $id); break;
            case 40: $id = hash('sha1', $id); break;
            case 64: $id = hash('sha256', $id); break;
            case 128: $id = hash('sha512', $id); break;
            default:
                throw new SessionException("No valid length option given, only '32,40,64,128' are accepted!");
        }

        return strtoupper($id);
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
