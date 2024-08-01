#!/usr/bin/env python3
"""A module for redacting logs containing sensitive information.
"""
import os
import re
import logging
import mysql.connector
from typing import List


patterns = {
    'extract': lambda fields, sep: rf'(?P<field>{"|".join(fields)})=[^{sep}]*',
    'replace': lambda redaction: rf'\g<field>={redaction}',
}
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str,
        ) -> str:
    """Redacts sensitive fields in a log message.
    """
    pattern_to_find = patterns["extract"](fields, separator)
    pattern_to_replace = patterns["replace"](redaction)
    return re.sub(pattern_to_find, pattern_to_replace, message)


def get_logger() -> logging.Logger:
    """Initializes a logger configured for handling user data logs.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Establishes a connection to a MySQL database.
    """
    connection = mysql.connector.connect(
        host=os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        port=3306,
        user=os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        password=os.getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        database=os.getenv("PERSONAL_DATA_DB_NAME", "")
    )
    return connection


def main():
    """Fetches and logs user data from a database,
    ensuring sensitive fields are redacted.
    """
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = f"SELECT {fields} FROM users;"

    info_logger = get_logger()
    connection = get_db()

    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record_items = [f'{col}={val}' for col, val in zip(columns, row)]
            message = '; '.join(record_items) + ';'
            log_record = logging.LogRecord(
                            "user_data", logging.INFO,
                            None, None, message, None, None
                        )
            info_logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """Formatter class that redacts specified fields in log messages.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Applies the redaction to the log message before returning it.
        """
        formatted_message = super().format(record)
        redacted_message = filter_datum(
                            self.fields, self.REDACTION, formatted_message,
                            self.SEPARATOR
                            )
        return redacted_message


if __name__ == "__main__":
    main()
