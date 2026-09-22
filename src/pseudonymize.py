"""Cria uma cópia pseudonimizada do contrato sem alterar o original."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
from pathlib import Path

from local_privacy import protect_output_parent

SENSITIVE_KEYS = {
    "display_name", "user_principal_name", "mail", "user_email", "email",
    "principal_name", "principal_id", "principal", "object_id", "resource_id",
    "subscription_id", "tenant_id", "app_id", "client_id", "owner", "publisher",
    "customer_name", "tenant_label",
}
EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")


def token(value: object, salt: str, prefix: str = "id") -> str:
    digest = hashlib.sha256(f"{salt}|{value}".encode("utf-8")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def transform(value: object, salt: str, key: str = "") -> object:
    if isinstance(value, dict):
        return {name: transform(child, salt, name.lower()) for name, child in value.items()}
    if isinstance(value, list):
        return [transform(child, salt, key) for child in value]
    if isinstance(value, str):
        if key == "id" and not re.fullmatch(r"(?:ID|SEC|GOV|COST)-\d+", value):
            return token(value, salt, "entity") if value else value
        if key in SENSITIVE_KEYS:
            return token(value, salt, "entity") if value else value
        return EMAIL.sub(lambda match: token(match.group(0), salt, "entity"), value)
    return value


def pseudonymize(data: dict, salt: str | None = None) -> dict:
    salt = salt or os.getenv("ASSESSMENT_PSEUDONYM_SALT") or secrets.token_hex(16)
    result = transform(copy.deepcopy(data), salt)
    metadata = result.setdefault("metadata", {})
    metadata["privacy_mode"] = "pseudonymized"
    metadata["privacy_note"] = "Identificadores foram pseudonimizados localmente; o salt não é armazenado no contrato."
    metadata["pseudonym_salt_fingerprint"] = hashlib.sha256(salt.encode("utf-8")).hexdigest()[:12]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera contrato pseudonimizado para compartilhamento")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--salt", default=None, help="Salt local opcional; nunca é gravado no output")
    args = parser.parse_args()
    protect_output_parent(args.output)
    data = json.loads(args.input.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(pseudonymize(data, args.salt), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Contrato pseudonimizado gravado em {args.output}")


if __name__ == "__main__":
    main()
