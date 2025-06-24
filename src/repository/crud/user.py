import time
import typing

import sqlalchemy
from sqlalchemy.sql import functions as sqlalchemy_functions

from src.models.db.user import User, UserTypeEnum
from src.models.schemas.user import UserInCreate, UserInLogin, UserInUpdate
from src.repository.crud.base import BaseCRUDRepository
from src.securities.hashing.password import pwd_generator
from src.securities.verifications.credentials import credential_verifier
from src.utilities.exceptions.database import EntityAlreadyExists, EntityDoesNotExist
from src.utilities.exceptions.password import PasswordDoesNotMatch


class UserCRUDRepository(BaseCRUDRepository):
    async def create_user(self, user_create: UserInCreate) -> User:
        new_user = User(
            username=user_create.username, 
            email=user_create.email, 
            is_logged_in=True,
            user_type=user_create.user_type.value if user_create.user_type else UserTypeEnum.RIDER.value,
            created_at=int(time.time())
        )

        new_user.set_hash_salt(hash_salt=pwd_generator.generate_salt)
        new_user.set_hashed_password(
            hashed_password=pwd_generator.generate_hashed_password(
                hash_salt=new_user.hash_salt, new_password=user_create.password
            )
        )

        self.async_session.add(instance=new_user)
        await self.async_session.commit()
        await self.async_session.refresh(instance=new_user)

        return new_user

    async def read_users(self) -> typing.Sequence[User]:
        stmt = sqlalchemy.select(User)
        query = await self.async_session.execute(statement=stmt)
        return query.scalars().all()

    async def read_user_by_id(self, id: int) -> User:
        stmt = sqlalchemy.select(User).where(User.id == id)
        query = await self.async_session.execute(statement=stmt)

        if not query:
            raise EntityDoesNotExist(f"User with id `{id}` does not exist!")

        return query.scalar()  # type: ignore

    async def read_user_by_username(self, username: str) -> User:
        stmt = sqlalchemy.select(User).where(User.username == username)
        query = await self.async_session.execute(statement=stmt)

        if not query:
            raise EntityDoesNotExist(f"User with username `{username}` does not exist!")

        return query.scalar()  # type: ignore

    async def read_user_by_email(self, email: str) -> User:
        stmt = sqlalchemy.select(User).where(User.email == email)
        query = await self.async_session.execute(statement=stmt)

        if not query:
            raise EntityDoesNotExist(f"User with email `{email}` does not exist!")

        return query.scalar()  # type: ignore

    async def read_user_by_password_authentication(self, user_login: UserInLogin) -> User:
        stmt = sqlalchemy.select(User).where(
            User.username == user_login.username
        )
        query = await self.async_session.execute(statement=stmt)
        db_user = query.scalar()

        if not db_user:
            raise EntityDoesNotExist("Wrong username or wrong email!")

        if not pwd_generator.is_password_authenticated(hash_salt=db_user.hash_salt, password=user_login.password, hashed_password=db_user.hashed_password):  # type: ignore
            raise PasswordDoesNotMatch("Password does not match!")

        return db_user  # type: ignore

    async def update_user_by_id(self, id: int, user_update: UserInUpdate) -> User:
        new_user_data = user_update.dict()
        select_stmt = sqlalchemy.select(User).where(User.id == id)
        query = await self.async_session.execute(statement=select_stmt)
        update_user = query.scalar()
        if not update_user:
            raise EntityDoesNotExist(f"User with id `{id}` does not exist!")  # type: ignore
        update_stmt = sqlalchemy.update(table=User).where(User.id == update_user.id).values(updated_at=int(time.time()))  # type: ignore

        if new_user_data["username"]:
            update_stmt = update_stmt.values(username=new_user_data["username"])

        if new_user_data["email"]:
            update_stmt = update_stmt.values(email=new_user_data["email"])
            
        if new_user_data["user_type"]:
            update_stmt = update_stmt.values(user_type=new_user_data["user_type"].value)

        if new_user_data["password"]:
            update_user.set_hash_salt(hash_salt=pwd_generator.generate_salt)  # type: ignore
            update_user.set_hashed_password(hashed_password=pwd_generator.generate_hashed_password(hash_salt=update_user.hash_salt, new_password=new_user_data["password"]))  # type: ignore

        await self.async_session.execute(statement=update_stmt)
        await self.async_session.commit()
        await self.async_session.refresh(instance=update_user)

        return update_user  # type: ignore

    async def delete_user_by_id(self, id: int) -> str:
        select_stmt = sqlalchemy.select(User).where(User.id == id)
        query = await self.async_session.execute(statement=select_stmt)
        delete_user = query.scalar()

        if not delete_user:
            raise EntityDoesNotExist(f"User with id `{id}` does not exist!")  # type: ignore

        stmt = sqlalchemy.delete(table=User).where(User.id == delete_user.id)

        await self.async_session.execute(statement=stmt)
        await self.async_session.commit()

        return f"User with id '{id}' is successfully deleted!"

    async def is_username_taken(self, username: str) -> bool:
        username_stmt = sqlalchemy.select(User.username).select_from(User).where(User.username == username)
        username_query = await self.async_session.execute(username_stmt)
        db_username = username_query.scalar()

        if not credential_verifier.is_username_available(username=db_username):
            raise EntityAlreadyExists(f"The username `{username}` is already taken!")  # type: ignore

        return True

    async def is_email_taken(self, email: str) -> bool:
        email_stmt = sqlalchemy.select(User.email).select_from(User).where(User.email == email)
        email_query = await self.async_session.execute(email_stmt)
        db_email = email_query.scalar()

        if not credential_verifier.is_email_available(email=db_email):
            raise EntityAlreadyExists(f"The email `{email}` is already registered!")  # type: ignore

        return True