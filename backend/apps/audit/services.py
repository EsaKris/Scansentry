from .models import AuditLog


def record_audit(*, actor=None, action, obj=None, object_type="", object_id="",
                 before=None, after=None, ip=None):
    """Write an audit entry. Audit data is only ever created server-side."""
    if obj is not None:
        object_type = object_type or obj.__class__.__name__
        object_id = object_id or str(obj.pk)
    return AuditLog.objects.create(
        actor=actor if getattr(actor, "is_authenticated", False) else None,
        action=action, object_type=object_type, object_id=object_id,
        before_state=before, after_state=after, ip_address=ip,
    )
