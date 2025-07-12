import os
import subprocess
import time
import webbrowser
from pathlib import Path
import secrets
import shutil
import requests
import click
from rich.console import Console
from rich.progress import Progress

CONFIG_FILE = Path.home() / ".sshclaude" / "config.yaml"
LAUNCHER_FILE = Path.home() / ".sshclaude" / "launch_claude.sh"
PLIST_FILE = Path.home() / "Library/LaunchAgents" / "com.sshclaude.tunnel.plist"
API_URL = os.getenv("SSHCLAUDE_API", "https://api.sshclaude.dev")
console = Console()


def ensure_config_dir():
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)


def install_ttyd():
    if shutil.which("ttyd"):
        console.print("[green]ttyd already installed.")
        return
    console.print("[bold]Installing ttyd via Homebrew...")
    subprocess.run(["env", "HOMEBREW_NO_AUTO_UPDATE=1", "brew", "install", "ttyd"], check=False)


def install_cloudflared():
    if shutil.which("cloudflared"):
        console.print("[green]cloudflared already installed.")
        return
    console.print("[bold]Installing cloudflared via Homebrew...")
    subprocess.run(["env", "HOMEBREW_NO_AUTO_UPDATE=1", "brew", "install", "cloudflared"], check=False)


def write_launcher(token: str) -> None:
    ensure_config_dir()
    token_file = CONFIG_FILE.parent / "session_token"
    token_file.write_text(token)

    guard_script = CONFIG_FILE.parent / "token_guard.sh"
    guard_script.write_text(f"""#!/bin/bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh"
nvm use node > /dev/null
EXPECTED=$(cat "{token_file}")
read -p "Token: " INPUT
if [ "$INPUT" != "$EXPECTED" ]; then
  echo "Unauthorized"
  exit 1
fi
exec claude
""")
    guard_script.chmod(0o755)

    LAUNCHER_FILE.write_text(f"""#!/bin/bash
exec ttyd --once {guard_script}
""")
    LAUNCHER_FILE.chmod(0o755)

def write_tunnel_files(subdomain: str, token: str) -> None:
    import json
    cf_dir = Path.home() / ".cloudflared"
    cf_dir.mkdir(parents=True, exist_ok=True)

    # Write token
    (cf_dir / "token.json").write_text(json.dumps({"tunnel_token": token}))

    # Write config with ingress rules
    config_text = f"""tunnel: {subdomain}
credentials-file: {cf_dir/'token.json'}
ingress:
  - service: http://localhost:7681
"""

    (cf_dir / "config.yml").write_text(config_text)


def _launchctl(action: str, plist: Path) -> None:
    if not shutil.which("launchctl"):
        return
    domain = f"gui/{os.getuid()}"
    subprocess.run(
        ["launchctl", action, domain, str(plist)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def write_plist(token: str) -> None:
    PLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    cloudflared_path = shutil.which("cloudflared") or "/usr/local/bin/cloudflared"
    plist = f"""<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
<plist version='1.0'>
<dict>
    <key>Label</key>
    <string>com.sshclaude.tunnel</string>
    <key>ProgramArguments</key>
    <array>
        <string>{cloudflared_path}</string>
        <string>tunnel</string>
        <string>run</string>
        <string>--token</string>
        <string>{token}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
    PLIST_FILE.write_text(plist)
    _launchctl("bootout", PLIST_FILE)
    _launchctl("bootstrap", PLIST_FILE)


def write_config(data: dict):
    import yaml
    ensure_config_dir()
    with CONFIG_FILE.open("w") as f:
        yaml.safe_dump(data, f)


def read_config() -> dict:
    import yaml
    if CONFIG_FILE.exists():
        with CONFIG_FILE.open() as f:
            return yaml.safe_load(f) or {}
    return {}


def is_tunnel_running() -> bool:
    plist_label = "com.sshclaude.tunnel"
    result = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
    return plist_label in result.stdout


def is_ttyd_running() -> bool:
    result = subprocess.run(["pgrep", "-f", "ttyd.*token_guard.sh"], capture_output=True, text=True)
    return result.returncode == 0



@click.group()
def cli():
    """sshclaude command line interface."""



@cli.command()
@click.option("--github", required=True, help="Your GitHub login (used for display only)")
@click.option("--domain", help="Subdomain to use (default: <user>.sshclaude.com)")
@click.option("--session", default="15m", help="Session TTL for Access")
@click.option("--token", help="Optional session token to unlock terminal (only stored locally)")
def init(github: str, domain: str | None, session: str, token: str | None):
    """Initialize a Claude tunnel after verifying GitHub identity."""

    console.print("[blue]sshclaude init started")

    config = read_config()
    if config:
        console.print("[yellow]Existing configuration found - reusing tunnel token.")
        subdomain = config.get("domain")
        tunnel_token = config.get("tunnel_token")
        if not subdomain or not tunnel_token:
            console.print("[red]Configuration incomplete. Remove ~/.sshclaude and re-run init.")
            return
        session_token = token.strip() if token else (CONFIG_FILE.parent / "session_token").read_text().strip()
        write_tunnel_files(subdomain, tunnel_token)
        write_launcher(session_token)
        write_plist(tunnel_token)
        # Check if ttyd is already running
        if is_ttyd_running():
            console.print("[yellow]ttyd already running — reusing existing terminal.")
        else:
            ttyd_proc = subprocess.Popen(["ttyd", "--port", "7681", str(CONFIG_FILE.parent / "token_guard.sh")])
            console.print(f"[dim]Started ttyd (PID {ttyd_proc.pid})[/]")

        # Restart tunnel if already active
        if is_tunnel_running():
            console.print("[yellow]Tunnel already running — restarting to apply config...")
            _launchctl("bootout", PLIST_FILE)

        _launchctl("bootstrap", PLIST_FILE)

        console.print(f"[green]sshclaude started at https://{subdomain}")
        return

    install_cloudflared()
    install_ttyd()

    console.print("[bold]Verifying GitHub identity via browser login...")
    try:
        resp = requests.post(f"{API_URL}/login", timeout=10)
        resp.raise_for_status()
        login = resp.json()
        client_id = login["client_id"]
    except Exception as e:
        console.print(f"[red]Failed to initiate login: {e}")
        return

    uid = login["url"].split("/")[-1]
    api_token = login["token"]

    import base64
    import json

    state_obj = {"uid": uid, "token": api_token}
    state = base64.urlsafe_b64encode(json.dumps(state_obj).encode()).decode()

    login_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri=https://api.sshclaude.dev/oauth/callback"
        f"&state={state}"
        f"&allow_signup=false"
        f"&scope=user:email"
    )

    webbrowser.open(login_url)
    console.print(f"[cyan]Waiting for verification... (or open {login_url} manually)")

    for _ in range(60):
        time.sleep(2)
        try:
            check = requests.get(f"{API_URL}/login/{uid}/status", timeout=5).json()
            if check.get("verified"):
                console.print("[green]GitHub identity verified.")
                break
        except Exception:
            pass
    else:
        console.print("[red]Verification timed out.")
        return

    try:
        userinfo = requests.get(
            f"{API_URL}/login/{uid}/whoami",
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=10,
        )
        userinfo.raise_for_status()
        verified_email = userinfo.json().get("email")
        if not verified_email:
            console.print("[red]Server did not return a verified email.")
            return
        console.print(f"[green]Verified email: {verified_email}")
    except Exception as e:
        console.print(f"[red]Failed to fetch verified email: {e}")
        return

    subdomain = domain or f"{os.getlogin()}.sshclaude.com"
    console.print("[bold]Provisioning tunnel and access policy...")

    try:
        resp = requests.post(
            f"{API_URL}/provision",
            json={
                "github_id": github,
                "email": verified_email,
                "subdomain": subdomain
            },
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        console.print(f"[red]Provisioning failed: {e}")
        return

    tunnel_token = data.get("tunnel_token")
    config = {
        "github_id": github,
        "domain": subdomain,
        "session": session,
        "tunnel_id": data.get("tunnel_id"),
        "tunnel_token": tunnel_token,
        "dns_record_id": data.get("dns_record_id"),
        "access_app_id": data.get("access_app_id"),
    }

    write_config(config)

    session_token = token.strip() if token else secrets.token_urlsafe(32)
    if not token:
        console.print(f"[bold yellow]Generated session token:[/] {session_token}")
        console.print("[dim]This token is required to unlock Claude in your browser.[/]")

    write_tunnel_files(subdomain, tunnel_token)
    write_launcher(session_token)
    write_plist(tunnel_token)

    console.print(f"[green]Initialization complete! Visit: https://{subdomain}")


@cli.command()
def stop():
    """Stop the sshclaude tunnel session (cloudflared + ttyd)."""
    console.print("[bold]Stopping sshclaude tunnel session...")

    if PLIST_FILE.exists():
        _launchctl("bootout", PLIST_FILE)
        console.print("[green]Stopped cloudflared tunnel.")
    else:
        console.print("[yellow]No active cloudflared session found.")

    # Kill any stray ttyd processes (only ones that launched claude)
    try:
        result = subprocess.run(
            ["pgrep", "-fl", "ttyd"],
            capture_output=True,
            text=True,
            check=False
        )
        for line in result.stdout.strip().split("\n"):
            if "ttyd" in line and "claude" in line:
                pid = int(line.split()[0])
                os.kill(pid, 9)
                console.print(f"[green]Killed ttyd process (PID {pid})")
    except Exception as e:
        console.print(f"[red]Failed to kill ttyd: {e}")

    console.print("[bold green]Tunnel session fully stopped.")


@cli.command()
def uninstall():
    config = read_config()
    if not config:
        console.print("[red]sshclaude not initialized.")
        return
    console.print("[bold]Removing Cloudflare resources...")
    subdomain = config.get("domain")
    with Progress() as progress:
        t = progress.add_task("cleanup", total=3)
        progress.update(t, advance=1)
        try:
            resp = requests.delete(
                f"{API_URL}/provision/{subdomain}",
                json={"tunnel_token": config.get("tunnel_token")},
                timeout=30,
            )
            if resp.status_code != 200:
                console.print(f"[red]Delete failed: {resp.text}")
                return
        except Exception as e:
            console.print(f"[red]Failed to delete resources: {e}")
            return
        progress.update(t, advance=2)

    _launchctl("bootout", PLIST_FILE)
    PLIST_FILE.unlink(missing_ok=True)
    LAUNCHER_FILE.unlink(missing_ok=True)
    CONFIG_FILE.unlink(missing_ok=True)
    console.print("[green]Uninstall complete.")

@cli.command(name="refresh-token")
def refresh_token():
    """Refresh Cloudflare tunnel token and update local config."""
    config = read_config()
    if not config:
        console.print("[red]sshclaude is not initialized.")
        return

    subdomain = config.get("domain")
    console.print(f"[bold]Refreshing tunnel token for {subdomain}...")

    try:
        resp = requests.post(f"{API_URL}/rotate-key/{subdomain}", timeout=30)
        resp.raise_for_status()
        data = resp.json()
        new_token = data.get("tunnel_token")
        if not new_token:
            console.print("[red]No token returned from server.")
            return
    except Exception as e:
        console.print(f"[red]Failed to refresh token: {e}")
        return

    # Update config and files
    config["tunnel_token"] = new_token
    write_config(config)
    write_tunnel_files(subdomain, new_token)

    # Reload tunnel
    _launchctl("bootout", PLIST_FILE)
    write_plist(new_token)
    _launchctl("bootstrap", PLIST_FILE)

    console.print("[green]Tunnel token refreshed successfully.")

if __name__ == "__main__":
    cli()

