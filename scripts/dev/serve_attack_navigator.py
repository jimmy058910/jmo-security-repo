#!/usr/bin/env python3
"""
Serve ATT&CK Navigator layer with automatic browser opening.

This script:
1. Starts a local HTTP server
2. Generates a custom HTML page with embedded ATT&CK layer
3. Opens browser to automatically load the layer
4. No manual file upload required!

Usage:
    python3 scripts/dev/serve_attack_navigator.py [attack-navigator.json]

Example:
    python3 scripts/dev/serve_attack_navigator.py results/summaries/attack-navigator.json
"""

import http.server
import json
import os
import socketserver
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Configuration
DEFAULT_JSON = "results/summaries/attack-navigator.json"
PORT = 8765
ATTACK_NAV_URL = "https://mitre-attack.github.io/attack-navigator/"


def generate_html(layer_json: dict) -> str:
    """Generate HTML page that auto-loads ATT&CK layer."""
    layer_json_str = json.dumps(layer_json, indent=2)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JMo Security - ATT&CK Navigator</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #7f8c8d;
            margin-bottom: 30px;
        }}
        .info-box {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin: 20px 0;
        }}
        .warning-box {{
            background: #fff3e0;
            border-left: 4px solid #ff9800;
            padding: 15px;
            margin: 20px 0;
        }}
        .button {{
            display: inline-block;
            background: #2196F3;
            color: white;
            padding: 12px 24px;
            border-radius: 4px;
            text-decoration: none;
            margin: 10px 10px 10px 0;
            transition: background 0.3s;
        }}
        .button:hover {{
            background: #1976D2;
        }}
        .button-success {{
            background: #4caf50;
        }}
        .button-success:hover {{
            background: #388E3C;
        }}
        pre {{
            background: #f5f5f5;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            max-height: 400px;
        }}
        code {{
            font-family: "Monaco", "Courier New", monospace;
            font-size: 14px;
        }}
        .step {{
            margin: 20px 0;
            padding-left: 30px;
            position: relative;
        }}
        .step::before {{
            content: "→";
            position: absolute;
            left: 0;
            color: #2196F3;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 JMo Security - ATT&CK Navigator</h1>
        <p class="subtitle">MITRE ATT&CK Threat Mapping</p>

        <div class="info-box">
            <strong>✓ Layer loaded successfully!</strong><br>
            Your security findings have been mapped to MITRE ATT&CK techniques.
        </div>

        <h2>Option 1: Automatic Upload (Recommended)</h2>
        <div class="step">
            <strong>Step 1:</strong> Copy the layer JSON to clipboard
            <button class="button button-success" onclick="copyToClipboard()">
                📋 Copy Layer JSON
            </button>
        </div>
        <div class="step">
            <strong>Step 2:</strong> Open ATT&CK Navigator
            <a href="{ATTACK_NAV_URL}" target="_blank" class="button" id="openNav">
                🌐 Open ATT&CK Navigator
            </a>
        </div>
        <div class="step">
            <strong>Step 3:</strong> In the Navigator:
            <ul>
                <li>Click the <strong>'+'</strong> button (top-left)</li>
                <li>Select <strong>'Open Existing Layer'</strong></li>
                <li>Click <strong>'Enter Layer JSON'</strong></li>
                <li>Paste the JSON (Ctrl+V or Cmd+V)</li>
                <li>Click <strong>'Load'</strong></li>
            </ul>
        </div>

        <h2>Option 2: Manual Download</h2>
        <div class="step">
            <a href="/layer.json" download="jmo-attack-layer.json" class="button">
                💾 Download Layer JSON
            </a>
            <p>Then upload via Navigator: <strong>'+' → 'Open Existing Layer' → 'Upload from local'</strong></p>
        </div>

        <div class="warning-box">
            <strong>Note:</strong> Due to browser security (CORS), direct loading requires manual paste.
            This is a limitation of ATT&CK Navigator, not JMo Security.
        </div>

        <h2>Layer Preview</h2>
        <pre><code id="layerJson">{layer_json_str}</code></pre>

        <h2>Techniques Detected</h2>
        <p>This layer contains mappings for the following ATT&CK techniques found in your scan:</p>
        <ul id="techniqueList"></ul>
    </div>

    <script>
        const layerData = {layer_json_str};

        // Copy to clipboard function
        function copyToClipboard() {{
            const jsonText = document.getElementById('layerJson').textContent;
            navigator.clipboard.writeText(jsonText).then(() => {{
                alert('✓ Layer JSON copied to clipboard!\\n\\nNow open ATT&CK Navigator and paste it.');
            }}).catch(err => {{
                console.error('Failed to copy:', err);
                alert('Failed to copy. Please select the JSON manually and copy with Ctrl+C.');
            }});
        }}

        // Auto-open Navigator after 2 seconds
        setTimeout(() => {{
            if (confirm('Open ATT&CK Navigator now?')) {{
                window.open('{ATTACK_NAV_URL}', '_blank');
                // Auto-copy after opening
                setTimeout(copyToClipboard, 1000);
            }}
        }}, 2000);

        // Extract techniques from layer
        if (layerData.techniques) {{
            const list = document.getElementById('techniqueList');
            layerData.techniques.forEach(tech => {{
                const li = document.createElement('li');
                li.innerHTML = `<strong>${{tech.techniqueID}}</strong>: ${{tech.score}} findings`;
                if (tech.comment) {{
                    li.innerHTML += ` <em>(${{tech.comment}})</em>`;
                }}
                list.appendChild(li);
            }});
        }}
    </script>
</body>
</html>
"""


class CustomHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler to serve ATT&CK layer."""

    layer_data = None

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/" or self.path == "/index.html":
            # Serve custom HTML page
            html_content = generate_html(self.layer_data)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_content.encode())))
            self.end_headers()
            self.wfile.write(html_content.encode())

        elif self.path == "/layer.json":
            # Serve raw JSON for download
            json_content = json.dumps(self.layer_data, indent=2)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=jmo-attack-layer.json")
            self.send_header("Content-Length", str(len(json_content.encode())))
            self.end_headers()
            self.wfile.write(json_content.encode())

        else:
            # 404 for other paths
            self.send_error(404, "File not found")

    def log_message(self, format, *args):
        """Suppress HTTP server logs."""
        pass


def serve_and_open(json_file: Path):
    """Start HTTP server and open browser."""

    # Load layer JSON
    try:
        with open(json_file, "r") as f:
            layer_data = json.load(f)
    except Exception as e:
        print(f"❌ Error loading JSON: {e}")
        sys.exit(1)

    # Set layer data in handler
    CustomHandler.layer_data = layer_data

    # Start server in background thread
    with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()

        url = f"http://localhost:{PORT}"
        print("=" * 60)
        print("🚀 JMo Security - ATT&CK Navigator Server")
        print("=" * 60)
        print(f"✓ Server running at: {url}")
        print(f"✓ Layer file: {json_file}")
        print(f"✓ Techniques: {len(layer_data.get('techniques', []))}")
        print("")
        print("Opening browser...")

        # Open browser
        time.sleep(1)
        webbrowser.open(url)

        print("")
        print("Press Ctrl+C to stop server")
        print("=" * 60)

        try:
            # Keep server alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n✓ Server stopped")


def main():
    """Main entry point."""
    # Parse arguments
    json_file = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_JSON)

    # Validate file
    if not json_file.exists():
        print(f"❌ Error: File not found: {json_file}")
        print("")
        print("Usage: python3 scripts/dev/serve_attack_navigator.py [attack-navigator.json]")
        print(f"Example: python3 scripts/dev/serve_attack_navigator.py {DEFAULT_JSON}")
        sys.exit(1)

    # Serve and open
    serve_and_open(json_file)


if __name__ == "__main__":
    main()
