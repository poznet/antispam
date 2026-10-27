<?php

namespace AntispamBundle\Security;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * The single administrator account, configured through the ADMIN_USER and
 * ADMIN_PASSWORD_HASH environment variables. Login is impossible while the
 * hash is empty.
 *
 * @implements UserProviderInterface<InMemoryUser>
 */
class AdminUserProvider implements UserProviderInterface
{
    private $username;
    private $passwordHash;

    public function __construct(
        #[Autowire('%env(ADMIN_USER)%')] string $username,
        #[Autowire('%env(ADMIN_PASSWORD_HASH)%')] string $passwordHash
    ) {
        $this->username = $username;
        $this->passwordHash = $passwordHash;
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        if ($this->username === '' || $this->passwordHash === '' || !hash_equals($this->username, $identifier)) {
            throw new UserNotFoundException();
        }

        return new InMemoryUser($this->username, $this->passwordHash, ['ROLE_ADMIN']);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof InMemoryUser) {
            throw new UnsupportedUserException(sprintf('Unsupported user class "%s".', get_class($user)));
        }

        return $this->loadUserByIdentifier($user->getUserIdentifier());
    }

    public function supportsClass(string $class): bool
    {
        return InMemoryUser::class === $class;
    }
}
