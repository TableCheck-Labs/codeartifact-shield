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


JSR_DEFAULT_API = "https://api.jsr.io"


def _split_jsr_name(package_name: str) -> tuple[str, str]:
    """Split a jsr package name ``@scope/name`` into ``(scope, name)``.

    The leading ``@`` is stripped from the scope. Raises ``ValueError`` for a
    name that isn't in ``@scope/name`` form.
    """
    if not package_name.startswith("@") or "/" not in package_name:
        raise ValueError(f"not a jsr @scope/name package: {package_name!r}")
    scope, name = package_name[1:].split("/", 1)
    return scope, name


@dataclass
class JsrEndpoint:
    """The jsr.io registry API — for querying jsr package publish times.

    jsr packages (``@scope/name``) carry a ``createdAt`` timestamp per version
    at ``/scopes/{scope}/packages/{name}/versions``. Used by ``cas cooldown``
    to age-gate deno.lock jsr dependencies the same way npm deps are gated.
    """

    url: str = JSR_DEFAULT_API
    label: str = "jsr.io"

    def versions_url(self, package_name: str) -> str:
        scope, name = _split_jsr_name(package_name)
        base = self.url.rstrip("/")
        scope_q = urllib.parse.quote(scope)
        name_q = urllib.parse.quote(name)
        return f"{base}/scopes/{scope_q}/packages/{name_q}/versions"


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
