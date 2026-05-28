import os
import shutil
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse

from analyzer import analyze_pcap


app = FastAPI(title="AI Network Traffic Analyzer")

UPLOAD_FOLDER = "captures"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AI Network Traffic Analyzer</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f5f7fb;
                margin: 0;
                padding: 30px;
            }
            .container {
                max-width: 900px;
                margin: auto;
                background: white;
                padding: 25px;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            }
            h1 {
                color: #1f4e79;
            }
            .box {
                background: #eef5ff;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 20px;
            }
            input, button {
                padding: 10px;
                margin-top: 10px;
            }
            button {
                background: #1f4e79;
                color: white;
                border: none;
                border-radius: 6px;
                cursor: pointer;
            }
            button:hover {
                background: #163b5c;
            }
            code {
                background: #eee;
                padding: 2px 5px;
                border-radius: 4px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>AI Network Traffic Analyzer</h1>

            <div class="box">
                <p>
                    Upload a saved <code>.pcap</code> or <code>.pcapng</code> file from Wireshark.
                    This app will summarize the traffic and flag unusual packets.
                </p>
            </div>

            <form action="/analyze" enctype="multipart/form-data" method="post">
                <input name="file" type="file" accept=".pcap,.pcapng">
                <br>
                <button type="submit">Analyze Capture</button>
            </form>
        </div>
    </body>
    </html>
    """


@app.post("/analyze", response_class=HTMLResponse)
def analyze(file: UploadFile = File(...)):

    filename = file.filename

    if not filename.endswith((".pcap", ".pcapng")):
        return HTMLResponse(
            content="<h2>Error: Please upload a .pcap or .pcapng file.</h2>",
            status_code=400
        )

    save_path = os.path.join(UPLOAD_FOLDER, filename)

    with open(save_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    result = analyze_pcap(save_path)

    summary = result["summary"]
    anomalies = result["anomalies"]
    notes = result["notes"]
    sample_packets = result["sample_packets"]

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Analysis Results</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f5f7fb;
                margin: 0;
                padding: 30px;
            }}
            .container {{
                max-width: 1100px;
                margin: auto;
                background: white;
                padding: 25px;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            }}
            h1, h2 {{
                color: #1f4e79;
            }}
            .card {{
                background: #eef5ff;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 20px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
                font-size: 14px;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background: #1f4e79;
                color: white;
            }}
            .warning {{
                background: #fff3cd;
                padding: 12px;
                border-radius: 8px;
                margin-bottom: 10px;
            }}
            a {{
                color: #1f4e79;
            }}
        </style>
    </head>
    <body>
    <div class="container">
        <h1>Analysis Results</h1>
        <p><a href="/">Upload another file</a></p>

        <div class="card">
            <h2>Traffic Summary</h2>
            <p><strong>Total Packets:</strong> {summary["total_packets"]}</p>
            <p><strong>Total Bytes:</strong> {summary["total_bytes"]}</p>
        </div>

        <div class="card">
            <h2>AI Security Notes</h2>
    """

    for note in notes:
        html += f"<div class='warning'>{note}</div>"

    html += """
        </div>

        <div class="card">
            <h2>Top Protocols</h2>
            <table>
                <tr><th>Protocol</th><th>Count</th></tr>
    """

    for protocol, count in summary["protocols"]:
        html += f"<tr><td>{protocol}</td><td>{count}</td></tr>"

    html += """
            </table>
        </div>

        <div class="card">
            <h2>Top Source IPs</h2>
            <table>
                <tr><th>Source IP</th><th>Count</th></tr>
    """

    for ip, count in summary["top_source_ips"]:
        html += f"<tr><td>{ip}</td><td>{count}</td></tr>"

    html += """
            </table>
        </div>

        <div class="card">
            <h2>Top Destination IPs</h2>
            <table>
                <tr><th>Destination IP</th><th>Count</th></tr>
    """

    for ip, count in summary["top_destination_ips"]:
        html += f"<tr><td>{ip}</td><td>{count}</td></tr>"

    html += """
            </table>
        </div>

        <div class="card">
            <h2>Top Destination Ports</h2>
            <table>
                <tr><th>Destination Port</th><th>Count</th></tr>
    """

    for port, count in summary["top_destination_ports"]:
        html += f"<tr><td>{port}</td><td>{count}</td></tr>"

    html += """
            </table>
        </div>

        <div class="card">
            <h2>Flagged Anomalies</h2>
            <table>
                <tr>
                    <th>#</th>
                    <th>Time</th>
                    <th>Protocol</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Length</th>
                </tr>
    """

    if len(anomalies) == 0:
        html += "<tr><td colspan='6'>No anomalies detected.</td></tr>"
    else:
        for packet in anomalies:
            html += f"""
                <tr>
                    <td>{packet["number"]}</td>
                    <td>{packet["timestamp"]}</td>
                    <td>{packet["protocol"]}</td>
                    <td>{packet["src_ip"]}:{packet["src_port"]}</td>
                    <td>{packet["dst_ip"]}:{packet["dst_port"]}</td>
                    <td>{packet["length"]}</td>
                </tr>
            """

    html += """
            </table>
        </div>

        <div class="card">
            <h2>Sample Packets</h2>
            <table>
                <tr>
                    <th>#</th>
                    <th>Protocol</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Length</th>
                    <th>Highest Layer</th>
                </tr>
    """

    for packet in sample_packets:
        html += f"""
            <tr>
                <td>{packet["number"]}</td>
                <td>{packet["protocol"]}</td>
                <td>{packet["src_ip"]}:{packet["src_port"]}</td>
                <td>{packet["dst_ip"]}:{packet["dst_port"]}</td>
                <td>{packet["length"]}</td>
                <td>{packet["highest_layer"]}</td>
            </tr>
        """

    html += """
            </table>
        </div>
    </div>
    </body>
    </html>
    """

    return HTMLResponse(content=html)