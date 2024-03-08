<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-session
 */
namespace froq\session;

/**
 * An abstract session handler.
 *
 * @package froq\session
 * @class   froq\session\SessionHandler
 * @author  Kerem Güneş
 * @since   1.0
 */
abstract class SessionHandler extends \SessionHandler
{
    /** Session instance. */
    protected Session $session;

    /**
     * Constructor.
     *
     * @param froq\session\Session $session
     */
    public final function __construct(Session $session)
    {
        $this->session = $session;

        // In behalf of this (final) constructor.
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

    // Note: If any following method defined in child class of this class then these
    // methods will be used in Froq! Session object. That can be useful when writing
    // session data into a database or anywhere instead default session files, or to
    // generate self-defined session ids. Remember all following id-related methods
    // must be defined in child class.

    // public function isValidId(string|null $id): bool { /* validate id */ }
    // public function isValidSource(string|null $id): bool { /* validate source by id */ }
    // public function generateId(): string { /* generate id */ }
}
