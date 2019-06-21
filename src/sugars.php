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

/**
 * Session.
 * @param string|array|null $key
 * @param any               $value
 * @return froq\session\Session|any
 */
function session($key = null, $value = null)
{
    static $session; if ($session == null) {
        $session = app()->service()->getSession();
    }

    // set/get
    if ($key && $session) {
        if (is_null($value)) {
            return $session->get($key);
        }
        $session->set($key, $value);
    }

    return $session;
}

/**
 * Session flash.
 * @param  any $message
 * @return any
 */
function session_flash($message = null)
{
    return ($session = session()) ? $session->flash($message) : null;
}

/**
 * Session array.
 * @return ?array
 */
function session_array(): ?array
{
    return ($session = session()) ? $session->toArray() : null;
}

/**
 * Session has.
 * @param  string $key
 * @return ?bool
 */
function session_has(string $key): ?bool
{
    return ($session = session()) ? $session->has($key) : null;
}

/**
 * Session set.
 * @param  string|array $key
 * @param  any          $value
 * @return ?bool
 */
function session_set($key, $value = null): ?bool
{
    return ($session = session()) ? !!$session->set($key, $value) : null;
}

/**
 * Session get.
 * @param  string|array $key
 * @param  any          $value
 * @return any
 */
function session_get($key, $value_default = null)
{
    return ($session = session()) ? $session->get($key, $value_default) : $value_default;
}

/**
 * Session remove.
 * @param  string|array $key
 * @return void
 */
function session_remove($key): void
{
    ($session = session()) && $session->remove($key);
}

/**
 * Start session.
 * @return ?bool
 */
function start_session(): ?bool
{
    return ($session = session()) ? $session->start() : null;
}

/**
 * End session.
 * @return ?bool
 */
function end_session(): ?bool
{
    return ($session = session()) ? $session->end() : null;
}
