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

use froq\session\Session;
use SessionHandlerInterface;

/**
 * Abstract Handler.
 * @package froq\session
 * @object  froq\session\AbstractHandler
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 */
abstract class AbstractHandler implements SessionHandlerInterface
{
    /**
     * Session.
     * @var froq\session\Session
     */
    protected Session $session;

    /**
     * Constructor.
     * @param froq\session\Session $session
     */
    public final function __construct(Session $session)
    {
        $this->session = $session;
    }

    /**
     * Get session.
     * @return froq\session\Session
     */
    public final function getSession(): Session
    {
        return $this->session;
    }

    // Note: If any following method defined in child class of this object then these
    // methods will be used in Froq! Session object. That could be useful when writing
    // session data into a database or anywhere instead default session files, or to
    // generate self-defined session ids. Remember all following id-related methods must
    // be defined in child class.

    // public function isValidId(string $id): bool { /* validate id */ }
    // public function isValidSource(string $id): bool { /* validate source by id */ }
    // public function generateId(): string { /* generate id */ }
}
