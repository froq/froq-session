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
use froq\common\traits\OptionTrait;
use froq\common\interfaces\Arrayable;
use froq\session\{SessionException, AbstractHandler};

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
     * Option trait.
     *
     * @see froq\common\traits\OptionTrait
     * @since 4.0
     */
    use OptionTrait;

    /**
     * Id.
     * @var ?string
     */
    private ?string $id;

    /**
     * name.
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
        'hash'     => true, 'hashLength' => 32, // ID length (32, 40)
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
        $options = array_merge(self::$optionsDefault, (array) ($options ?? []));
        $options['cookie'] = array_merge(self::$optionsDefault['cookie'], (array) ($options['cookie'] ?? []));

        $this->setOptions($options);

        $savePath = $options['savePath'];
        if ($savePath != null) {
            if (!is_dir($savePath)) {
                $ok =@ mkdir($savePath, 0644, true);
                if (!$ok) {
                    throw new SessionException('Cannot make directory [error: %s]', ['@error']);
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
                    throw new SessionException('Both handler and handler file are required');
                }
                if (!is_file($saveHandlerFile)) {
                    throw new SessionException('Could not find given handler file "%s"', [$saveHandlerFile]);
                }
                require_once $saveHandlerFile;
            }

            if (!class_exists($saveHandler, true)) {
                throw new SessionException('Handler class "%s" not found', [$saveHandler]);
            }
            if (!is_subclass_of($saveHandler, AbstractHandler::class, true)) {
                throw new SessionException('Handler class must extend "%s" object', [AbstractHandler::class]);
            }

            // Init handler.
            $saveHandler = new $saveHandler($this);

            session_set_save_handler($saveHandler, true);

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
            $id = session_id();
            $idUpdate = false;
            $name = $this->options['name'];

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
            $this->id = $id;
            $this->name = $name;

            if ($idUpdate) {
                // @note If id is specified, it will replace the current session id. session_id() needs to be called
                // before session_start() for that purpose. @from http://php.net/manual/en/function.session-id.php
                session_id($this->id);
            }
            session_name($this->name);

            if (headers_sent($file, $line)) {
                throw new SessionException('Cannot use "%s()", headers already sent in "%s:%s"',
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

        return ($this->started = $started);
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
                // Fix: "Unrecognized key 'lifetime' found".
                $cookieParams = session_get_cookie_params();
                $cookieParams['expires'] = $cookieParams['lifetime'];
                unset($cookieParams['lifetime']);

                setcookie($this->getName(), '', $cookieParams);
            }
        }

        return ($this->ended = $ended);
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
                $idPattern = '~^[A-F0-9]{'. $this->options['hashLength'] .'}$~';
            } else {
                // @see http://php.net/manual/en/session.configuration.php#ini.session.sid-length
                // @see http://php.net/manual/en/session.configuration.php#ini.session.sid-bits-per-character
                // @see https://github.com/php/php-src/blob/PHP-7.1/UPGRADING#L114
                $idLenDefault = '26';
                $idBitsPerCharDefault = '5';

                $idLen = ini_get('session.sid_length') ?: $idLenDefault;
                $idBitsPerChar = ini_get('session.sid_bits_per_character');
                if ($idBitsPerChar == '') { // Never happens, but obsession..
                    ini_set('session.sid_length', $idLenDefault);
                    ini_set('session.sid_bits_per_character', ($idBitsPerChar = $idBitsPerCharDefault));
                }

                $idChars = '';
                switch ($idBitsPerChar) {
                    case '4': $idChars = '0-9a-f'; break;
                    case '5': $idChars = '0-9a-v'; break;
                    case '6': $idChars = '0-9a-zA-Z-,'; break;
                }

                $idPattern = '~^['. $idChars .']{'. $idLen .'}$~';
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
                case 32: $id = hash('md5', $id); break;
                case 40: $id = hash('sha1', $id); break;
                default:
                    throw new SessionException('Invalid "hashLength" option "%s", valids are: 32, 40'.
                        [$this->options['hashLength']]);
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
        $name = $this->getName();

        return $name && isset($_SESSION[$name][$key]);
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
            throw new SessionException('Cannot modify "@" key in session data');
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
     * @param  any|null                  $valueDefault
     * @param  bool                      $remove
     * @return any
     */
    public function get($key, $valueDefault = null, bool $remove = false)
    {
        $name = $this->getName();

        if (isset($_SESSION[$name])) {
            return is_array($key)
                ? Arrays::getAll($_SESSION[$name], $key, $valueDefault, $remove)
                : Arrays::get($_SESSION[$name], $key, $valueDefault, $remove);
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
            throw new SessionException('Cannot modify "@" key in session data');
        }

        // No value assign or return, so just for dropping fields with "true".
        $this->get((array) $key, null, true);
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
     * @inheritDoc froq\common\interfaces\Arrayable
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
