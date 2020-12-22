<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\session;

use froq\session\Session;
use SessionHandlerInterface;

/**
 * Abstract Handler.
 *
 * @package froq\session
 * @object  froq\session\AbstractHandler
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 */
abstract class AbstractHandler implements SessionHandlerInterface
{
    /** @var froq\session\Session */
    protected Session $session;

    /**
     * Constructor.
     *
     * @param froq\session\Session $session
     */
    public final function __construct(Session $session)
    {
        $this->session = $session;

        if (method_exists($this, 'init')) {
            $this->init();
        }
    }

    /**
     * Get session property.
     *
     * @return froq\session\Session
     */
    public final function session(): Session
    {
        return $this->session;
    }

    // Note: If any following method defined in child class of this object then these
    // methods will be used in Froq! Session object. That can be useful when writing
    // session data into a database or anywhere instead default session files, or to
    // generate self-defined session ids. Remember all following id-related methods must
    // be defined in child class.

    // public function isValidId(string $id): bool { /* validate id */ }
    // public function isValidSource(string $id): bool { /* validate source by id */ }
    // public function generateId(): string { /* generate id */ }
}
