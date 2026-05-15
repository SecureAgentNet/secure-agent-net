from typing import Tuple
from src.decide.models import EvaluationRequest

class RuleFilter:
    """
    Tier 1 Evaluation: Fast, deterministic rule checking.
    Blocks known malicious patterns, paths, and actions.
    """
    
    # Hardcoded for prototyping. In production, this loads from the DB `policies` table.
    DENY_ACTIONS = {"delete_database", "format_drive", "exfiltrate_keys"}
    DANGEROUS_PATHS = {"/etc/shadow", "/etc/passwd", ".aws/credentials", ".kube/config", "/root"}
    
    @classmethod
    def evaluate(cls, request: EvaluationRequest) -> Tuple[bool, float, str]:
        """
        Returns (is_blocked, risk_score, reason)
        If is_blocked is True, the pipeline halts immediately.
        """
        if request.action_name in cls.DENY_ACTIONS:
            return True, 1.0, f"Action '{request.action_name}' is explicitly denied."
            
        # Check target resource against dangerous paths
        for path in cls.DANGEROUS_PATHS:
            if path in request.target_resource:
                return True, 0.9, f"Target resource contains restricted path: {path}"
                
        # Deep inspection of string payloads
        for key, value in request.payload.items():
            if isinstance(value, str):
                for path in cls.DANGEROUS_PATHS:
                    if path in value:
                        return True, 0.9, f"Payload field '{key}' contains restricted path."
                        
        return False, 0.0, "Passed RuleFilter"
