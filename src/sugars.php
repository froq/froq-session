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
 * @return Froq\Session\Session
 */
function session()
{
    static $session;
    if ($session == null) {
        $session = app()->service()->getSession();
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
    return session()->flash($message);
}

/**
 * Session array.
 * @return array
 */
function session_array(): array
{
    return session()->toArray();
}

/**
 * Has session value.
 * @param  string $key
 * @return bool
 */
function has_session_value(string $key): bool
{
    return session()->has($key);
}

/**
 * Set session value.
 * @param  string|array $key
 * @param  any          $value
 * @return void
 */
function set_session_value($key, $value = null): void
{
    session()->set($key, $value);
}

/**
 * Get session value.
 * @param  string|array $key
 * @param  any          $value
 * @return any
 */
function get_session_value($key, $value_default = null)
{
    return session()->get($key, $value_default);
}

/**
 * Remove session value.
 * @param  string|array $key
 * @return void
 */
function remove_session_value($key): void
{
    session()->remove($key);
}

/**
 * Start session.
 * @return bool
 */
function start_session(): bool
{
    return session()->start();
}

/**
 * End session.
 * @return bool
 */
function end_session(): bool
{
    return session()->end();
}
