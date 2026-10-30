"""Social login endpoints: Google and GitHub (v4 /auth/oauth/).

Fail-closed contract:
- provider disabled / unconfigured -> 503
- bad or stale ``state``           -> 400
- provider rejects the code        -> 401
- email already registered         -> 409
"""

import logging

from ninja_extra import api_controller, route

from apps.common.response import CustomResponse
from apps.common.schemas import DataResponse, ErrorResponse
from apps.common.exceptions import AuthenticationError, ConflictError
from .oauth_social import (
    AuthStateError,
    ProviderUnavailableError,
    SocialOAuthService,
    build_authorize_url,
)
from .schemas import (
    LoginResponseDataSchema,
    SocialAuthorizeResponseSchema,
    SocialExchangeSchema,
)

logger = logging.getLogger("apps.accounts")


@api_controller("/auth/oauth", tags=["Auth OAuth"], auth=None)
class OauthSocialController:
    @route.get(
        "/{provider}/authorize/",
        response={200: DataResponse[SocialAuthorizeResponseSchema], 503: ErrorResponse},
    )
    async def authorize(self, request, provider: str, redirect_uri: str):
        """Return the provider authorize URL and the signed state to echo back."""
        try:
            authorize_url, state = build_authorize_url(provider, redirect_uri)
        except ProviderUnavailableError:
            return CustomResponse.error(
                message="This sign-in provider is not available.",
                code="provider_unavailable",
                status_code=503,
            )
        return CustomResponse.success(
            message=f"Authorize URL generated for {provider}",
            data={"authorize_url": authorize_url, "state": state},
        )

    @route.post(
        "/{provider}/exchange/",
        response={
            200: DataResponse[LoginResponseDataSchema],
            400: ErrorResponse,
            401: ErrorResponse,
            409: ErrorResponse,
            503: ErrorResponse,
        },
    )
    async def exchange(self, request, provider: str, data: SocialExchangeSchema):
        """Exchange an authorization code for a login token pair."""
        try:
            user, tokens, expires_at, key_salt = await SocialOAuthService.exchange_and_login(
                provider=provider,
                code=data.code,
                redirect_uri=data.redirect_uri,
                state=data.state,
            )
        except ProviderUnavailableError:
            return CustomResponse.error(
                message="This sign-in provider is not available.",
                code="provider_unavailable",
                status_code=503,
            )
        except AuthStateError:
            return CustomResponse.error(
                message="Sign-in session is invalid or expired. Try again.",
                code="invalid_state",
                status_code=400,
            )
        except ConflictError as exc:
            return CustomResponse.error(
                message=str(exc),
                code="already_exists",
                status_code=409,
            )
        except AuthenticationError as exc:
            logger.info("social login rejected provider=%s: %s", provider, exc)
            return CustomResponse.error(
                message="Sign-in with this provider failed.",
                code="invalid_credentials",
                status_code=401,
            )

        workspaces = await SocialOAuthService.workspaces(user)
        return CustomResponse.success(
            message="Login successful!",
            data={
                **tokens,
                "expires_at": expires_at,
                "key_salt": key_salt,
                "encrypted_private_key": None,
                "vault": None,
                "vault_version": None,
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "public_key": user.public_key,
                    "billing_id": user.billing_id,
                },
                "workspaces": workspaces,
            },
        )
