<?php
/**
 * Copyright (c) 2016 Kerem Güneş
 *    <k-gun@mail.com>
 *
 * GNU General Public License v3.0
 *    <http://www.gnu.org/licenses/gpl-3.0.txt>
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

/**
 * @package    Froq
 * @subpackage Froq\Session
 * @object     Froq\Session\SessionHandler
 * @author     Kerem Güneş <k-gun@mail.com>
 */
abstract class SessionHandler implements SessionHandlerInterface
{
    /**
     * Session.
     * @var Froq\Session\Session
     */
    protected $session;

    /**
     * Constructor.
     * @param Froq\Session\Session $session
     */
    final public function __construct(Session $session)
    {
        $this->session = $session;
    }

    /**
     * Get session.
     * @return Froq\Session\Session
     */
    final public function getSession(): Session
    {
        return $this->session;
    }
}
