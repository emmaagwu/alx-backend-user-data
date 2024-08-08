#!/usr/bin/env python3
"""Module for session authentication with expiration for the API.
"""
import os
from flask import request
from datetime import datetime, timedelta

from .session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """Handles session authentication with support for expiration."""

    def __init__(self) -> None:
        """Sets up a new instance of SessionExpAuth."""
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION', '0'))
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """Generates a session ID for the user."""
        session_id = super().create_session(user_id)
        if isinstance(session_id, str):
            self.user_id_by_session_id[session_id] = {
                'user_id': user_id,
                'created_at': datetime.now(),
            }
            return session_id
        return None

    def user_id_for_session_id(self, session_id=None) -> str:
        """Fetches the user ID linked to a specified session ID."""
        if session_id is None or session_id not in self.user_id_by_session_id:
            return None

        session_data = self.user_id_by_session_id[session_id]
        if self.session_duration <= 0:
            return session_data['user_id']

        if 'created_at' not in session_data:
            return None

        current_time = datetime.now()
        exp_duration = timedelta(seconds=self.session_duration)
        expiration_time = session_data['created_at'] + exp_duration
        if current_time > expiration_time:
            return None

        return session_data['user_id']
