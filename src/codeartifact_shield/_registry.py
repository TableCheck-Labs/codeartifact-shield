"""Shared registry-endpoint primitives.

Used by both ``cas cooldown`` (to consult publish-time metadata) and
``cas audit`` (to confirm package existence on a trusted endpoint when
OSV has no record). Centralised so the deployment-scenario logic
(npm-only / npm+CA / CA-only) is identical across commands.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass


@dataclass
class RegistryEndpoint:
    """One registry to consult.

    Attributes:
        url: Base URL, e.g. ``https://registry.npmjs.org`` or
            ``https://<domain>-<owner>.d.codeartifact.<region>.amazonaws.com/npm/<repo>``.
        auth_header: Optional ``Authorization`` header value
            (e.g. ``Bearer <token>``).
        label: Short identifier surfaced in human-readable output.
            Defaults to the URL host.
    """

    url: str
    auth_header: str | None = None
    label: str = ""

    def __post_init__(self) -> None:
        if not self.label:
            parsed = urllib.parse.urlparse(self.url)
            self.label = parsed.netloc or self.url


def package_url(endpoint: RegistryEndpoint, package_name: str) -> str:
    """Build the GET URL for one package's metadata on a registry."""
    base = endpoint.url.rstrip("/")
    return f"{base}/{urllib.parse.quote(package_name, safe='@')}"


def build_codeartifact_endpoint(
    domain: str,
    repository: str,
    domain_owner: str | None = None,
    region: str | None = None,
) -> RegistryEndpoint:
    """Construct a CodeArtifact npm endpoint with a fresh bearer token.

    Calls ``boto3`` for both the authorization token and the repository
    endpoint URL. Raises any underlying ``botocore`` exception unmodified
    so the CLI surfaces a clear authentication error.
    """
    import boto3

    client = boto3.client("codeartifact", region_name=region)
    if domain_owner:
        token_resp = client.get_authorization_token(
            domain=domain, domainOwner=domain_owner
        )
        endpoint_resp = client.get_repository_endpoint(
            domain=domain,
            domainOwner=domain_owner,
            repository=repository,
            format="npm",
        )
    else:
        token_resp = client.get_authorization_token(domain=domain)
        endpoint_resp = client.get_repository_endpoint(
            domain=domain, repository=repository, format="npm"
        )
    token = token_resp["authorizationToken"]
    endpoint_url = endpoint_resp["repositoryEndpoint"].rstrip("/")
    return RegistryEndpoint(
        url=endpoint_url,
        auth_header=f"Bearer {token}",
        label=urllib.parse.urlparse(endpoint_url).netloc,
    )
