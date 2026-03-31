import json
import hashlib


def serialize_po_data(po_number, item_description, quantity, cost, justification, created_by, created_at):
    po_data = {
        "po_number": po_number,
        "item_description": item_description,
        "quantity": quantity,
        "cost": cost,
        "justification": justification,
        "created_by": created_by,
        "created_at": created_at
    }

    return json.dumps(po_data, sort_keys=True)


def generate_po_hash(po_number, item_description, quantity, cost, justification, created_by, created_at):
    serialized_data = serialize_po_data(
        po_number,
        item_description,
        quantity,
        cost,
        justification,
        created_by,
        created_at
    )

    return hashlib.sha256(serialized_data.encode("utf-8")).hexdigest()


def recompute_hash_for_po(po):
    """
    Strongest fix:
    Always use the exact timestamp string that was originally used when the PO hash was created.
    """
    return generate_po_hash(
        po_number=po.po_number,
        item_description=po.item_description,
        quantity=po.quantity,
        cost=po.cost,
        justification=po.justification,
        created_by=po.created_by,
        created_at=po.created_at_hash_string
    )