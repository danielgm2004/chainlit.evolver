import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt as pyjwt

from chainlit.config import config
from chainlit.logger import logger
from chainlit.user import User


def get_jwt_secret() -> Optional[str]:
    return os.environ.get("CHAINLIT_AUTH_SECRET")


def create_jwt(data: User) -> str:
    # Create minimal JWT payload to avoid chunking issues
    # Only include essential fields, not the full metadata
    minimal_payload = {
        "identifier": data.identifier,
        "display_name": data.display_name,
        # Only include essential metadata fields
        "metadata": {
            "provider": data.metadata.get("provider"),
            "role": data.metadata.get("role"),
            "email": data.metadata.get("email"),
            "company_id": data.metadata.get("company_id"),
        },
        "exp": datetime.now(timezone.utc)
        + timedelta(seconds=config.project.user_session_timeout),
        "iat": datetime.now(timezone.utc),
    }

    secret = get_jwt_secret()
    assert secret
    encoded_jwt = pyjwt.encode(minimal_payload, secret, algorithm="HS256")
    
    # Log token size to verify it's under chunking threshold
    logger.info(f"create_jwt: token_length={len(encoded_jwt)} user={data.identifier}")
    if len(encoded_jwt) > 3000:
        logger.warning(f"create_jwt: token still exceeds chunking threshold ({len(encoded_jwt)} > 3000)")
    
    return encoded_jwt


def decode_jwt(token: str) -> User:
    secret = get_jwt_secret()
    assert secret

    dict = pyjwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        options={"verify_signature": True},
    )
    del dict["exp"]
    return User(**dict)
