from flask import flash
from datetime import datetime
from config import Config
import pytz

def strtobool (val):
    val = val.lower().strip()
    if val in ('y', 'yes', 't', 'true', 'on', '1', 'vrai', 'o', 'x', 'oui'):
        return 1
    elif val in ('n', 'no', 'f', 'false', 'off', '0', 'faux','', 'non'):
        return 0
    else:
        flash("invalid truth value %r" % (val,))

def utc_date(obj):
    """Helper method to convert date object to UTC"""
    if isinstance(obj, datetime):
        return pytz.timezone(Config.LOCAL_TIMEZONE).localize(obj, is_dst=True).astimezone(pytz.utc)
    else:
         return None

def parse_date(date_str):
    """Helper method to parse various date formats"""
    if not date_str:
        return None

    formats = [
        '%d/%m/%Y %H:%M:%S',
        '%d/%m/%Y %H:%M',
        '%d/%m/%Y',
        '%d-%m-%Y %H:%M:%S',
        '%d-%m-%Y %H:%M',
        '%d-%m-%Y',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S'
    ]

    for fmt in formats:
        try:
            print(f"[utils]Format détecté : {fmt} --> {datetime.strptime(date_str, fmt)}")
            return datetime.strptime(date_str, fmt)
        except (ValueError, TypeError):
            continue
    return None

def validate_date(date_str):
    if isinstance(date_str, str):
        parsed_date = parse_date(date_str)
        if parsed_date is None:
            print('Invalid date format. Please use correct date formatting')
        utc_date(parsed_date)
        return parsed_date