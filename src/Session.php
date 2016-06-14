<?php
/**
 * Copyright (c) 2016 Kerem Güneş
 *     <k-gun@mail.com>
 *
 * GNU General Public License v3.0
 *     <http://www.gnu.org/licenses/gpl-3.0.txt>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
declare(strict_types=1);

namespace Froq\Session;

use Froq\Encryption\Salt;
use Froq\Util\Traits\{SingleTrait, GetterTrait};

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
     * Getter.
     * @var Froq\Util\Traits\GetterTrait
     */
    use GetterTrait;

    /**
     * ID.
     * @var string
     */
    private $id;

    /**
     * name.
     * @var string
     */
    private $name;

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
     * Options.
     * @var array
     */
    private $options = [
        'name'             => 'SID',
        'domain'           => '',
        'path'             => '/',
        'secure'           => false,
        'httponly'         => false,
        'lifetime'         => 0,
        'length'           => 32, // ID length
        'length_default'   => 32,
        'length_available' => [32, 40, 64, 128],
    ];

    /**
     * Constructor.
     * @param array $options
     */
    final private function __construct(array $options = null)
    {
        // merge options
        if ($options) {
            $this->options = array_merge($this->options, $options);
        }

        $this->name = $this->options['name'];

        // check/set length
        if (!in_array($this->options['length'], $this->options['length_available'])) {
            $this->options['length'] = $this->options['length_default'];
        }

        // session is active?
        if (!$this->isStarted || session_status() != PHP_SESSION_ACTIVE) {
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
    final public function __destruct()
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
    final public function __set(string $key, $value)
    {
        if (!isset($_SESSION[$this->name])) {
            // stop writing first
            session_abort();

            throw new SessionException(sprintf(
                "Session not started yet, call first '%s::start()' or use isset() first!",
                    __class__
            ));
        }

        $_SESSION[$this->name][$key] = $value;
    }

    /**
     * Get magic.
     * @param  string $key
     * @return any
     * @throws Froq\Session\SessionException
     */
    final public function __get(string $key)
    {
        if (!isset($_SESSION[$this->name])) {
            throw new SessionException(sprintf(
                "Session not started yet, call first '%s::start()' or use isset() first!",
                    __class__
            ));
        }

        return array_key_exists($key, $_SESSION[$this->name])
            ? $_SESSION[$this->name][$key] : null;
    }

    /**
     * Isset magic.
     * @param  string $key
     * @return bool
     * @throws Froq\Session\SessionException
     */
    final public function __isset(string $key)
    {
        if (!isset($_SESSION[$this->name])) {
            throw new SessionException(sprintf(
                "Session not started yet, call first '%s::start()' or use isset() first!",
                    __class__
            ));
        }

        return array_key_exists($key, $_SESSION[$this->name]);
    }

    /**
     * Unset magic.
     * @param  string $key
     * @return void
     * @throws Froq\Session\SessionException
     */
    final public function __unset(string $key)
    {
        if (!isset($_SESSION[$this->name])) {
            throw new SessionException(sprintf(
                "Session not started yet, call first '%s::start()' or use isset() first!",
                    __class__
            ));
        }

        unset($_SESSION[$this->name][$key]);
    }

    /**
     * Set.
     * @param  string $key
     * @param  any    $value
     * @return self
     */
    final public function set(string $key, $value): self
    {
        $this->__set($key, $value);

        return $this;
    }

    /**
     * Set all.
     * @param  array $data
     * @return self
     */
    final public function setAll(array $data): self
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
    final public function get(string $key, $valueDefault = null)
    {
        return (null !== ($value = $this->__get($key)))
            ? $value : $valueDefault;
    }

    /**
     * Get all.
     * @param  array $keys
     * @return array
     */
    final public function getAll(array $keys): array
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
    final public function remove(string $key): self
    {
        $this->__unset($key);

        return $this;
    }

    /**
     * Remove all.
     * @param  array $keys
     * @return self
     */
    final public function removeAll(array $keys): self
    {
        foreach ($keys as $key) {
            $this->__unset($key);
        }

        return $this;
    }

    /**
     * Get id.
     * @return string|null
     */
    final public function getId()
    {
        return $this->id;
    }

    /**
     * Get name.
     * @return string|null
     */
    final public function getName()
    {
        return $this->name;
    }

    /**
     * Get options.
     * @return array
     */
    final public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Is started.
     * @return bool
     */
    final public function isStarted(): bool
    {
        return $this->isStarted;
    }

    /**
     * Is destroyed.
     * @return bool
     */
    final public function isDestroyed(): bool
    {
        return $this->isDestroyed;
    }

    /**
     * Is valid ID.
     * @param  string $id
     * @return bool
     */
    final public function isValidId(string $id): bool
    {
        // see self.generateId()
        return ((bool) preg_match('~^[A-F0-9]{'. $this->options['length'] .'}$~', $id));
    }

    /**
     * Is valid file.
     * @param  string $id
     * @return bool
     */
    final public function isValidFile(string $id): bool
    {
        return is_file(sprintf('%s/sess_%s', ini_get('session.save_path'), $id));
    }

    /**
     * Start.
     * @return bool
     * @throws Froq\Session\SessionException
     */
    final public function start(): bool
    {
        if ($this->isStarted) {
            return true;
        }

        // check headers
        if (headers_sent($file, $line)) {
            throw new SessionException(sprintf(
                "Call '%s()' before outputs have been sent. [output location: '%s:%s']",
                    __method__, $file, $line
            ));
        }

        // app
        $app = app();

        // set/check id
        $id = session_id();
        if ($this->isValidId($id)) {
            $this->id = $id;
        } else {
            $id = $app->request->cookies->get($this->name, '');
            // hard and hard..
            if ($this->isValidId($id) && $this->isValidFile($id)) {
                $this->id = $id;
            } else {
                // generate new one
                $this->id = $this->generateId();
            }
        }

        /**
         * Note: When using session cookies, specifying an id for session_id() will always send a new
         * cookie when session_start() is called, regardless if the current session id is identical to
         * the one being set. */
        // set session id
        session_id($this->id);

        // start session
        $this->isStarted = session_start();
        if (!$this->isStarted) {
            // stop writing first
            session_write_close();

            throw new SessionException(sprintf(
                "Session start is failed in '%s()'", __method__));
        }

        // init subpart
        if (!isset($_SESSION[$this->name])) {
            $_SESSION[$this->name] = [];
        }

        return $this->isStarted;
    }

    /**
     * Destroy.
     * @param  bool $deleteCookie
     * @return bool
     */
    final public function destroy(bool $deleteCookie = true): bool
    {
        if (!$this->isDestroyed) {
            $this->isDestroyed = session_destroy();
            if ($this->isDestroyed) {
                $this->reset();
            }
            if ($deleteCookie) {
                $this->deleteCookie();
            }
        }

        $this->id = null;

        return $this->isDestroyed;
    }

    /**
     * Delete cookie.
     * @return void
     */
    final public function deleteCookie()
    {
        if (isset($_COOKIE[$this->name])) {
            $cookieParams = session_get_cookie_params();
            setcookie($this->name, '', 0,
                $cookieParams['path'],
                $cookieParams['domain'],
                $cookieParams['secure'],
                $cookieParams['httponly']
            );
        }
    }

    /**
     * Generate id.
     * @return string
     */
    final function generateId(): string
    {
        $id = Salt::generate(Salt::LENGTH, false);

        // encode by length
        switch ($this->options['length']) {
            case  32: $id = hash('md5', $id); break;
            case  40: $id = hash('sha1', $id); break;
            case  64: $id = hash('sha256', $id); break;
            case 128: $id = hash('sha512', $id); break;
        }

        return strtoupper($id);
    }

    /**
     * Regenerate id.
     * @param  bool $deleteOldSession
     * @return bool
     * @throws Froq\Session\SessionException
     */
    final public function regenerateId(bool $deleteOldSession = true): bool
    {
        // check headers sent?
        if (headers_sent($file, $line)) {
            throw new SessionException(sprintf(
                "Call to '%s()' after outputs have been sent. [output location is '%s:%s']",
                    __method__, $file, $line
            ));
        }

        $return = session_regenerate_id($deleteOldSession);

        // store session id
        $this->id = session_id($this->generateId());

        return $return;
    }

    /**
     * Flash.
     * @param  any $message
     * @return any
     */
    final public function flash($message = null)
    {
        // set
        if ($message !== null) {
            return $this->set('@flash', $message);
        }

        $message = $this->get('@flash');

        // remove
        $this->remove('@flash');

        return $message;

    }

    /**
     * Reset.
     * @return void
     */
    final private function reset()
    {
        $_SESSION[$this->name] = [];
    }

    /**
     * To array.
     * @return array
     */
    final public function toArray(): array
    {
        $array = [];
        if (isset($_SESSION[$this->name])) {
            $array = to_array($_SESSION[$this->name], true);
        }

        return $array;
    }
}
