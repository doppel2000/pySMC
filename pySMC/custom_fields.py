from wtforms import Field
from wtforms.widgets import TextInput
from datetime import timedelta


def parse_duration(value):
    try:
        if value == "":
            return None
        parts = value.split()
        days = 0
        time_parts = parts[-1].split(':')

        if len(parts) > 1:
            days = int(parts[0])

        if len(time_parts) == 2:
            hours, minutes = map(int, time_parts)
            seconds = 0
        elif len(time_parts) == 3:
            hours, minutes, seconds = map(int, time_parts)
        else:
            raise ValueError("Time must be in 'HH:MM' or 'HH:MM:SS' format")

        return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
    except ValueError:
        return None


class DurationField(Field):
    widget = TextInput()

    def _value(self):
        if self.data:
            days = self.data.days
            seconds = self.data.seconds
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            if days:
                day_str = "day" if days == 1 else "days"
                return f"{days} {day_str} {hours:02d}:{minutes:02d}:{seconds:02d}"
            else:
                return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return ""

    def process_formdata(self, valuelist):
        if valuelist:
            self.data = parse_duration(valuelist[0])
        else:
            self.data = None
            