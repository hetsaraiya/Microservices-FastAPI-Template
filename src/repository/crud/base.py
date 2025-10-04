from typing import TypeVar, Generic, Type, Optional, List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession as SQLAlchemyAsyncSession
from sqlalchemy import select, update, delete, func
from sqlalchemy.orm import DeclarativeBase

ModelType = TypeVar("ModelType", bound=DeclarativeBase)


class BaseCRUDRepository(Generic[ModelType]):
    """
    Base repository class providing common CRUD operations.
    
    This class provides reusable methods for standard database operations,
    reducing code duplication across repository implementations.
    """
    
    def __init__(self, async_session: SQLAlchemyAsyncSession, model: Type[ModelType] = None):
        self.async_session = async_session
        self.model = model
    
    async def create(self, **kwargs) -> ModelType:
        """
        Create a new record in the database.
        
        Args:
            **kwargs: Field values for the new record
            
        Returns:
            The created model instance
        """
        instance = self.model(**kwargs)
        self.async_session.add(instance)
        await self.async_session.commit()
        await self.async_session.refresh(instance)
        return instance
    
    async def get_by_id(self, id: Any) -> Optional[ModelType]:
        """
        Get a record by its ID.
        
        Args:
            id: The ID of the record to retrieve
            
        Returns:
            The model instance or None if not found
        """
        stmt = select(self.model).where(self.model.id == id)
        result = await self.async_session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_by_field(self, field_name: str, value: Any) -> Optional[ModelType]:
        """
        Get a record by a specific field value.
        
        Args:
            field_name: Name of the field to filter by
            value: Value to match
            
        Returns:
            The model instance or None if not found
        """
        stmt = select(self.model).where(getattr(self.model, field_name) == value)
        result = await self.async_session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[ModelType]:
        """
        Get all records with pagination.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of model instances
        """
        stmt = select(self.model).offset(skip).limit(limit)
        result = await self.async_session.execute(stmt)
        return list(result.scalars().all())
    
    async def update_by_id(self, id: Any, **kwargs) -> Optional[ModelType]:
        """
        Update a record by its ID.
        
        Args:
            id: The ID of the record to update
            **kwargs: Fields to update with their new values
            
        Returns:
            The updated model instance or None if not found
        """
        # First get the instance
        instance = await self.get_by_id(id)
        if not instance:
            return None
        
        # Update fields
        for key, value in kwargs.items():
            if hasattr(instance, key) and value is not None:
                setattr(instance, key, value)
        
        await self.async_session.commit()
        await self.async_session.refresh(instance)
        return instance
    
    async def delete_by_id(self, id: Any) -> bool:
        """
        Delete a record by its ID.
        
        Args:
            id: The ID of the record to delete
            
        Returns:
            True if deleted, False if not found
        """
        stmt = delete(self.model).where(self.model.id == id)
        result = await self.async_session.execute(stmt)
        await self.async_session.commit()
        return result.rowcount > 0
    
    async def count(self, **filters) -> int:
        """
        Count records matching the given filters.
        
        Args:
            **filters: Field name and value pairs to filter by
            
        Returns:
            Count of matching records
        """
        stmt = select(func.count()).select_from(self.model)
        for field_name, value in filters.items():
            stmt = stmt.where(getattr(self.model, field_name) == value)
        result = await self.async_session.execute(stmt)
        return result.scalar()
    
    async def exists(self, **filters) -> bool:
        """
        Check if any record exists matching the given filters.
        
        Args:
            **filters: Field name and value pairs to filter by
            
        Returns:
            True if at least one record exists, False otherwise
        """
        count = await self.count(**filters)
        return count > 0
    
    async def bulk_create(self, instances: List[Dict[str, Any]]) -> List[ModelType]:
        """
        Create multiple records in a single transaction.
        
        Args:
            instances: List of dictionaries containing field values
            
        Returns:
            List of created model instances
        """
        model_instances = [self.model(**data) for data in instances]
        self.async_session.add_all(model_instances)
        await self.async_session.commit()
        
        # Refresh all instances
        for instance in model_instances:
            await self.async_session.refresh(instance)
        
        return model_instances
