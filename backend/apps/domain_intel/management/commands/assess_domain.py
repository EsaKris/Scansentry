"""Live smoke test: run a real assessment from this machine and print a readable summary.

    python manage.py assess_domain example.com
    python manage.py assess_domain https://example.com --json

Use it after deployment (and from the server's network) to confirm RDAP, DNS, TLS and website checks
work end to end. It stores the assessment like a normal lookup (anonymous).
"""
import json

from django.core.management.base import BaseCommand, CommandError
from rest_framework.utils.encoders import JSONEncoder

from apps.domain_intel import service
from apps.domain_intel.normalize import InvalidDomainInput
from apps.domain_intel.presenters import present


class Command(BaseCommand):
    help = "Run a live domain assessment and print the result."

    def add_arguments(self, parser):
        parser.add_argument("value", help="Domain name or URL")
        parser.add_argument("--json", action="store_true", help="Print the full JSON result")
        parser.add_argument("--refresh", action="store_true", help="Ignore cached results")

    def handle(self, *args, **opts):
        try:
            assessment, cached = service.assess(opts["value"], user=None, refresh=False)
        except InvalidDomainInput as exc:
            raise CommandError(str(exc))
        data = present(assessment, cached=cached)
        if opts["json"]:
            self.stdout.write(json.dumps(data, cls=JSONEncoder, indent=2))
            return
        reg, web, health = data["registration"], data["website"] or {}, data["scores"]["domain_health"]
        w = self.stdout.write
        w(f"Domain:            {data['domain']}  (registrable: {data['registrable_domain']})")
        w(f"Completion:        {data['completion_status']}   confidence: {data['confidence']}   cached: {cached}")
        w(f"Registration:      {reg['status']}  flags={reg['raw_status_flags']}")
        w(f"  created:         {reg['created_at']}  age_days={reg['age_days']} ({reg['age_group']})")
        w(f"  registrar:       {reg['registrar']}   RDAP: {reg['rdap_source']}")
        w(f"DNS:               {(data['dns'] or {}).get('status')}")
        w(f"TLS:               {(data['tls'] or {}).get('status')}")
        w(f"Website:           {web.get('hosting_status')} HTTP {web.get('http_status')} ({web.get('confidence')})")
        w(f"Domain health:     {health['score']} ({health['label']}); not assessed: {health['not_assessed']}")
        for m in data["missing_checks"]:
            w(f"MISSING CHECK:     {m['check']} - {m['reason']}")
        for e in data["provider_errors"]:
            w(f"PROVIDER ERROR:    {e}")
