from collections import OrderedDict

from app.schemas.forensics import ForensicReport

_reports: OrderedDict[str, ForensicReport] = OrderedDict()
_MAX_REPORTS = 100


def store_report(report: ForensicReport) -> None:
    _reports[report.incident["incident_id"]] = report
    _reports.move_to_end(report.incident["incident_id"])
    while len(_reports) > _MAX_REPORTS:
        _reports.popitem(last=False)


def get_report(incident_id: str) -> ForensicReport | None:
    return _reports.get(incident_id)