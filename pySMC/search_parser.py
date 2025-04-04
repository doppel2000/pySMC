from pyparsing import Word, alphanums, Literal, oneOf, infixNotation, opAssoc, ParseException, QuotedString
from sqlalchemy import or_, and_, not_, func

from pySMC.custom_fields import parse_duration
from pySMC.models import Job, Status, Line
from datetime import datetime, timedelta
import operator

VALID_FIELDS = {
    'line', 'wo', 'batch', 'status', 'state', 'planned_date', 'duration', 'planned_qty', 'exact_qty',
    'remaining_qty', 'is_pq', 'item', 'description', 'setup', 'prio_date'
}

OPERATORS = {
    '<': operator.lt,
    '<=': operator.le,
    '>': operator.gt,
    '>=': operator.ge,
    '=': operator.eq
}


def parse_value(value, field):
    """Convert string value to appropriate type based on field."""
    if field in ['planned_date', 'prio_date']:
        # Try different date formats
        for fmt in ['%Y-%m-%d', '%Y-%m', '%Y']:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        return None
    elif field in ['planned_qty']:
        try:
            return float(value)
        except ValueError:
            return None
    elif field in ['duration']:
        return parse_duration(value)
    elif field in ['exact_qty', 'remaining_qty', 'is_pq']:
        return value.lower() == 'true'
    else:
        return value


def create_field_condition(field, value, op=None):
    if field not in VALID_FIELDS:
        print(f"Warning: Unknown field '{field}'. This condition will be ignored.")
        return True

    if '*' in value or '?' in value:
        value = value.replace('*', '%').replace('?', '_')

    parsed_value = parse_value(value, field)

    if parsed_value is None:
        return True

    if field in ['status', 'state']:
        column = getattr(Status, field)
    elif field == 'line':
        column = Line.description
    else:
        column = getattr(Job, field)

    if op is None or op == ':':
        return func.lower(column).like(func.lower(f'%{parsed_value}%'))
    else:
        return OPERATORS[op](column, parsed_value)


def parse_search_query(query):
    # For simple searches without field specifiers or operators
    if ':' not in query and ' ' not in query and '<' not in query and '>' not in query and '=' not in query:
        query = query.replace('*', '%').replace('?', '_')
        search_term = func.lower(f"%{query}%")

        return or_(
            func.lower(Line.description).like(search_term),
            func.lower(Job.wo).like(search_term),
            func.lower(Job.batch).like(search_term),
            func.lower(Status.status).like(search_term),
            func.lower(Status.state).like(search_term),
            func.lower(Job.item).like(search_term),
            func.lower(Job.description).like(search_term)
        )

    # Define basic elements
    word = Word(alphanums + "*?-:;.,")
    quoted_string = QuotedString('"', escChar='\\')
    term = quoted_string | word

    # Define comparison operators
    comp_op = oneOf("< <= = >= >")

    # Define field search
    field = Word(alphanums + "_")
    field_search = (
            (field + comp_op + term) |
            (field + Literal(":").suppress() + comp_op + term) |
            (field + Literal(":").suppress() + term)
    ).setParseAction(
        lambda t: create_field_condition(t[0], t[-1], t[1] if len(t) == 3 else None)
    )

    # Define operators
    and_op = oneOf("et ET and AND +")
    or_op = oneOf("ou OU or OR")
    not_op = oneOf("pas PAS not NOT ! -")

    # Define the grammar
    expr = infixNotation(
        field_search | term,
        [
            (not_op, 1, opAssoc.RIGHT, lambda t: not_(t[0][1])),
            (and_op, 2, opAssoc.LEFT, lambda t: and_(*t[0][::2])),
            (or_op, 2, opAssoc.LEFT, lambda t: or_(*t[0][::2])),
        ],
        )

    try:
        parsed = expr.parseString(query, parseAll=True)
        return parsed[0]
    except ParseException as e:
        print(f"Error parsing search query: {e}")
        return None


def apply_search_conditions(query, search_conditions):
    if search_conditions is not None:
        return query.filter(search_conditions)
    return query
