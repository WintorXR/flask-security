"""
    flask_security.datastore
    ~~~~~~~~~~~~~~~~~~~~~~~~

    This module contains an user datastore classes.

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2022 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    Complete;ly rewritten to just use sessions and no more queries.
"""

import datetime
import typing as t
import uuid

from sqlalchemy import func
from sqlalchemy.orm import joinedload
from sqlalchemy.future import select


class SQLAlchemySessionUserDatastore:
    """
    Data store for users. We can also do without when more and more stuff from flask security is being removed.
    """        
  
    def __init__(self, session: "sqlalchemy.orm.scoping.scoped_session", user_model: "User", role_model: "Role"):
        self.session = session
        self.user_model = user_model
        self.role_model = role_model
        
    def commit(self):
        self.session.commit()

    def find_role(self, role: str) -> t.Union["Role", None]:
        """
        Find a role and return object
        Args:
            role (str): name of role

        Returns:
            Role: object
        """
        return self.session.scalars(select(self.role_model).filter_by(name=role)).first()  # type: ignore

    def find_user(self, case_insensitive: bool = False, **kwargs: t.Any) -> t.Union["User", None]:
        """
            Find a user based on arbitrary fields
        Args:
            case_insensitive (bool): if case-insensitive should be removed
            **kwargs (dict): any other kwargs

        Returns:
            User: object
        """
 
        query = select(self.user_model)
        if hasattr(self.user_model, "roles"):
            query = query.options(joinedload(self.user_model.roles))

        if case_insensitive:
            # While it is of course possible to pass in multiple keys to filter on
            # that isn't the normal use case. If caller asks for case_insensitive
            # AND gives multiple keys - throw an error.
            if len(kwargs) > 1:
                raise ValueError("Case insensitive option only supports single key")
            attr, identifier = kwargs.popitem()
            subquery = func.lower(getattr(self.user_model, attr)) == func.lower(identifier)
            return self.session.scalars(query.filter(subquery)).first()
        else:
            return self.session.scalars(query.filter_by(**kwargs)).first()

    def _prepare_create_user_args(self, **kwargs: t.Any) -> dict[str, t.Any]:
        kwargs.setdefault("active", True)
        roles = kwargs.get("roles", [])
        for i, role in enumerate(roles):
            rn = role.name if isinstance(role, self.role_model) else role
            # see if the role exists
            roles[i] = self.find_role(rn)
        kwargs["roles"] = roles
        kwargs.setdefault("fs_uniquifier", uuid.uuid4().hex)
        if hasattr(self.user_model, "fs_token_uniquifier"):
            kwargs.setdefault("fs_token_uniquifier", uuid.uuid4().hex)
        if hasattr(self.user_model, "fs_webauthn_user_handle"):
            kwargs.setdefault("fs_webauthn_user_handle", uuid.uuid4().hex)

        return kwargs

    def _prepare_role_modify_args(self, role: t.Union[str, "Role"]) -> t.Union["Role", None]:
        if isinstance(role, str):
            return self.find_role(role)
        return role
        
    def delete_user(self, user: "User") -> None:
        """
            Delete a user
        Args:
            user (User): object to be deleted
        """
        self.session.delete(user)

    def create_user(self, **kwargs: t.Any) -> "User":
        """
            Create a user from the arguments given and return object
        Args:
            **kwargs (dict): user info0

        Returns:
            User: with data
        """
        kwargs = self._prepare_create_user_args(**kwargs)
        self.session.add(user := self.user_model(**kwargs))
        self.commit()
        return user

    def create_role(self, **kwargs: t.Any) -> "Role":
        """
        Creates and returns a new role from the given parameters.
        Supported params (depending on RoleModel):

        :kwparam name: Role name
        :kwparam permissions: a comma delimited list of permissions, a set or a list.
            These are user-defined strings that correspond to strings used with
            @permissions_required()

            .. versionadded:: 3.3.0
        """
        if "permissions" in kwargs and hasattr(self.role_model, "permissions"):
            perms = kwargs["permissions"]
            if isinstance(perms, list) or isinstance(perms, set):
                perms = ",".join(perms)
            elif isinstance(perms, str):
                perms = ",".join(p.strip() for p in perms.split(","))
            kwargs["permissions"] = perms

        return self.session.add(self.role_model(**kwargs))

    def find_or_create_role(self, name: str, **kwargs: t.Any) -> "Role":
        """Returns a role matching the given name or creates it with any
        additionally provided parameters.
        """
        return self.find_role(name) or self.create_role(name=name, **kwargs)

    def set_token_uniquifier(self, user: "User", uniquifier: t.Union[str, None] = None) -> None:
        """Set user's auth token identity key.
        This will immediately render outstanding auth tokens invalid.

        :param user: User to modify
        :param uniquifier: Unique value - if none then uuid.uuid4().hex is used

        This method is a no-op if the user model doesn't contain the attribute
        ``fs_token_uniquifier``

        .. versionadded:: 4.0.0
        """
        uniquifier = uniquifier if uniquifier else uuid.uuid4().hex
        if hasattr(user, "fs_token_uniquifier"):
            user.fs_token_uniquifier = uniquifier
            self.commit()

    def set_uniquifier(self, user: "User", uniquifier: t.Union[str, None] = None) -> None:
        """Set user's Flask-Security identity key.
        This will immediately render outstanding auth tokens,
        session cookies and remember cookies invalid.

        :param user: User to modify
        :param uniquifier: Unique value - if none then uuid.uuid4().hex is used

        .. versionadded:: 3.3.0
        """
        user.fs_uniquifier = uniquifier if uniquifier else uuid.uuid4().hex
        self.commit()

    def activate_user(self, user: "User") -> bool:
        """Activates a specified user. Returns `True` if a change was made.

        :param user: The user to activate
        """
        if not user.active:
            user.active = True
            self.commit()
        return user.active

    def deactivate_user(self, user: "User") -> bool:
        """Deactivates a specified user. Returns `True` if a change was made.

        This will immediately disallow access to all endpoints that require
        authentication either via session or tokens.
        The user will not be able to log in again.

        :param user: The user to deactivate
        """
        if user.active:
            user.active = False
            self.commit()
        return not user.active

    def toggle_active(self, user: "User") -> bool:
        """Toggles a user's active status. Always returns True."""
        user.active = not user.active
        self.commit()
        return True

    def remove_permissions_from_role(self, role: t.Union["Role", str], permissions: t.Union[set, list, str]) -> bool:
        """Remove one or more permissions from a role.

        :param role: The role to modify. Can be a Role object or
            string role name
        :param permissions: a set, list, or single string.
        :return: True if permissions removed, False if role doesn't exist.

        Caller must commit to DB.

        .. versionadded:: 4.0.0
        """
        if (role_obj := self._prepare_role_modify_args(role)):
            role_obj.remove_permissions(permissions)
            self.commit()
        return bool(role_obj)

    def add_permissions_to_role(self, role: t.Union["Role", str], permissions: t.Union[set, list, str]) -> bool:
        """Add one or more permissions to role.

        :param role: The role to modify. Can be a Role object or
            string role name
        :param permissions: a set, list, or single string.
        :return: True if permissions added, False if role doesn't exist.

        Caller must commit to DB.

        .. versionadded:: 4.0.0
        """
        
        if (role_obj := self._prepare_role_modify_args(role)):
            role_obj.add_permissions(permissions)
            self.commit()
        return bool(role_obj)

    def remove_role_from_user(self, user: "User", role: t.Union["Role", str]) -> bool:
        """Removes a role from a user.

        :param user: The user to manipulate. Can be an User object or email
        :param role: The role to remove from the user. Can be a Role object or
            string role name
        :return: True if role was removed, False if role doesn't exist or user didn't
            have role.
        """
        if (role_obj := self._prepare_role_modify_args(role)) in user.roles:
            user.roles.remove(role_obj)
            self.commit()
        return bool(role_obj)

    def add_role_to_user(self, user: "User", role: t.Union["Role", str]) -> bool:
        """Adds a role to a user.

        :param user: The user to manipulate.
        :param role: The role to add to the user. Can be a Role object or
            string role name
        :return: True is role was added, False if role already existed.
        """
        
        if not (role_obj := self._prepare_role_modify_args(role)):
            raise ValueError(f"Role: {role} doesn't exist")
        if role_obj not in user.roles:
            user.roles.append(role_obj)
            self.commit()
        return bool(role_obj)


if t.TYPE_CHECKING:  # pragma: no cover
    # Normally - the application creates the Models and glues them together
    # For typing we do that here since we don't know which DB interface they
    # will pick.
    from .core import UserMixin, RoleMixin

    class User(UserMixin):
        id: int
        email: str
        username: t.Optional[str]
        password: str
        active: bool
        fs_uniquifier: str
        fs_token_uniquifier: str
        fs_webauthn_user_handle: str
        confirmed_at: t.Optional[datetime.datetime]
        last_login_at: datetime.datetime
        current_login_at: datetime.datetime
        last_login_ip: t.Optional[str]
        current_login_ip: t.Optional[str]
        login_count: int
        tf_primary_method: t.Optional[str]
        tf_totp_secret: t.Optional[str]
        tf_phone_number: t.Optional[str]
        tf_recovery_codes: t.Optional[t.List[str]]
        us_phone_number: t.Optional[str]
        us_totp_secrets: t.Optional[t.Union[str, bytes]]
        create_datetime: datetime.datetime
        update_datetime: datetime.datetime
        roles: t.List["Role"]

        def __init__(self, **kwargs):
            ...

    class Role(RoleMixin):
        id: int
        name: str
        description: t.Optional[str]

        def __init__(self, **kwargs):
            ...
