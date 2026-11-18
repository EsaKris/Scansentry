import calendar
from datetime import datetime, timedelta


def add_interval(dt: datetime, interval: str) -> datetime:
    """Calendar-aware period arithmetic (a month from Jan 31 is Feb 28/29, not 30 days)."""
    if interval == "week":
        return dt + timedelta(days=7)
    months = {"month": 1, "quarter": 3, "year": 12}[interval]
    month_index = dt.month - 1 + months
    year, month = dt.year + month_index // 12, month_index % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)
