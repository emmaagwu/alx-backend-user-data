#!/usr/bin/env python3
"""Module providing session authentication with expiration
and storage capabilities for the API.
"""

from flask import request
from datetime import datetime, timedelta

from models.user_session import UserSession
from .session_exp_auth import SessionExpAuth


class SessionDBAuth(SessionExpAuth):
    """Handles session authentication with expiration and persistent storage."""

    def create_session(self, user_id=None) -> str:
        """Generates and saves a session ID for the specified user."""
        session_id = super().create_session(user_id)
        if isinstance(session_id, str):
            user_session = UserSession(
                user_id=user_id,
                session_id=session_id
            )
            user_session.save()
            return session_id
        return None

    def user_id_for_session_id(self, session_id=None):
        """Fetches the user ID linked to the provided session ID."""
        if session_id is None:
            return None

        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return None

        if not sessions:
            return None

        session = sessions[0]
        if datetime.now() > session.created_at + timedelta(seconds=self.session_duration):
            return None

        return session.user_id

    def destroy_session(self, request=None) -> bool:
        """Removes the session associated with the current request."""
        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return False

        if not sessions:
            return False

        sessions[0].remove()
        return True
