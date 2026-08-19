from typing import Any, Generic, TypeVar, List, Dict
from django.db.models import QuerySet
from ninja import Schema
from pydantic import Field

T = TypeVar("T")


class PaginationQuerySchema(Schema):
    page: int = Field(default=1, ge=1, description="Page number")
    limit: int = Field(default=50, ge=1, le=1000, description="Items per page")


class PaginatedResponseSchema(Schema, Generic[T]):
    items: List[T]
    total: int
    page: int
    limit: int
    pages: int


def paginate_queryset(queryset: QuerySet[Any], page: int = 1, limit: int = 50) -> dict[str, Any]:
    """
    Evaluates SQL-level LIMIT and OFFSET on the queryset without in-memory conversion.
    """
    total = queryset.count()
    offset = (page - 1) * limit
    items = list(queryset[offset : offset + limit])
    pages = (total + limit - 1) // limit if limit > 0 else 1
    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": pages,
    }
