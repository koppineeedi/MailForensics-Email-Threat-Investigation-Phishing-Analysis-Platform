from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.models import EmailSample, EmailAddress, EmailDomain, URLItem, Attachment, PhishingFinding, CaseEmail, EmailCase
from app.schemas.schemas import RelationshipGraph, GraphNode, GraphEdge
from app.api.deps import get_current_user

router = APIRouter(prefix="/api", tags=["Relationship Graph"])

@router.get("/emails/{id}/relationships", response_model=RelationshipGraph)
def get_email_relationship_graph(id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    
    return build_graph_for_samples([sample], db)

@router.get("/relationships", response_model=RelationshipGraph)
def get_global_relationship_graph(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    samples = db.query(EmailSample).limit(50).all()
    return build_graph_for_samples(samples, db)

def build_graph_for_samples(samples: List[EmailSample], db: Session) -> RelationshipGraph:
    nodes = []
    edges = []
    seen_nodes = set()
    seen_edges = set()

    def add_node(node_id: str, label: str, n_type: str, props: dict = None):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append(GraphNode(id=node_id, label=label, type=n_type, properties=props or {}))

    def add_edge(edge_id: str, source: str, target: str, label: str, evidence: str = None):
        if edge_id not in seen_edges and source in seen_nodes and target in seen_nodes:
            seen_edges.add(edge_id)
            edges.append(GraphEdge(id=edge_id, source=source, target=target, label=label, evidence=evidence))

    for sample in samples:
        e_node_id = f"email_{sample.id}"
        add_node(e_node_id, sample.subject or sample.original_filename, "EMAIL", {
            "sha256": sample.sha256,
            "risk_score": sample.risk_score,
            "risk_category": sample.risk_category
        })

        # Sender Node
        if sample.sender:
            sender_id = f"sender_{sample.sender}"
            add_node(sender_id, sample.sender, "SENDER")
            add_edge(f"edge_{e_node_id}_{sender_id}", e_node_id, sender_id, "SENT_BY", f"From header address: {sample.sender}")

        # Domain Nodes
        for d in sample.domains:
            d_id = f"domain_{d.domain}"
            add_node(d_id, d.domain, "DOMAIN", {"is_lookalike": d.is_lookalike, "is_punycode": d.is_punycode})
            add_edge(f"edge_{e_node_id}_{d_id}", e_node_id, d_id, f"HAS_DOMAIN_{d.domain_type}", f"Domain associated with {d.domain_type}")

        # URL Nodes
        for u in sample.urls:
            url_id = f"url_{u.id}"
            add_node(url_id, u.hostname or u.original_url[:30], "URL", {"full_url": u.original_url, "is_ip_based": u.is_ip_based})
            add_edge(f"edge_{e_node_id}_{url_id}", e_node_id, url_id, "CONTAINS_URL", f"Extracted from {u.source_location}")

            if u.ip_address:
                ip_id = f"ip_{u.ip_address}"
                add_node(ip_id, u.ip_address, "IP")
                add_edge(f"edge_{url_id}_{ip_id}", url_id, ip_id, "RESOLVES_TO_IP", "URL host is raw IP address")

        # Attachment Nodes & Hashes
        for att in sample.attachments:
            att_id = f"att_{att.id}"
            add_node(att_id, att.filename, "ATTACHMENT", {"extension": att.extension, "mime": att.mime_type})
            add_edge(f"edge_{e_node_id}_{att_id}", e_node_id, att_id, "HAS_ATTACHMENT", f"File size: {att.size_bytes} bytes")

            hash_id = f"hash_{att.sha256}"
            add_node(hash_id, att.sha256[:12] + "...", "HASH", {"sha256": att.sha256})
            add_edge(f"edge_{att_id}_{hash_id}", att_id, hash_id, "HAS_SHA256", f"SHA256: {att.sha256}")

        # Case Associations
        for case_assoc in sample.case_associations:
            case_obj = case_assoc.case
            if case_obj:
                c_id = f"case_{case_obj.id}"
                add_node(c_id, case_obj.case_number, "CASE", {"status": case_obj.status, "title": case_obj.title})
                add_edge(f"edge_{e_node_id}_{c_id}", e_node_id, c_id, "LINKED_TO_CASE", f"Case {case_obj.case_number}")

    return RelationshipGraph(nodes=nodes, edges=edges)
