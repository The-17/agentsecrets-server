# Standard library
from math import ceil


class CustomResponse:
    """
    Response helpers for Django Ninja controllers.

    Produces the exact same JSON shape as the original API
    to maintain full CLI compatibility:

        Success: {"status": "success", "message": "...", "data": {...}}
        Paginated: {"status": "success", "message": "...", "data": [...], "pagination": {...}}
    """

    @staticmethod
    def success(
        message: str,
        data=None,
        status_code: int = 200,
        paginate: bool = False,
        page: int = 1,
        per_page: int = 10,
        total: int = 0,
        is_drf: bool = False,
    ):
        response_data = {
            "status": "success",
            "message": message,
        }

        if paginate and data is not None:
            total_pages = ceil(total / per_page) if per_page > 0 else 1
            response_data["data"] = data
            response_data["pagination"] = {
                "count": total,
                "per_page": per_page,
                "current_page": page,
                "last_page": total_pages,
            }
        elif data is not None:
            response_data["data"] = data

        if is_drf:
            from rest_framework.response import Response
            return Response(response_data, status=status_code)

        if status_code != 200:
            return status_code, response_data
        return response_data

    @staticmethod
    def error(message: str, code: str = "error", data=None, status_code: int = 400, is_drf: bool = False):
        response_data = {
            "status": "failure",
            "code": code,
            "message": message,
        }
        if data is not None:
            response_data["data"] = data

        if is_drf:
            from rest_framework.response import Response
            return Response(response_data, status=status_code)

        return status_code, response_data