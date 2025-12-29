#!/usr/bin/env python3
"""
Convierte resultados JSON del scanner a reportes HTML profesionales
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

def json_to_html(json_file):
    """Convierte un archivo JSON a HTML"""
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Extraer información
        target = data.get('target', 'Unknown')
        scan_type = data.get('scan_type', 'Unknown')
        timestamp = data.get('timestamp', 'Unknown')
        
        # Crear nombre de archivo HTML
        html_file = json_file.replace('.json', '_report.html')
        
        # Generar HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 Network Scan Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        
        body {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(90deg, #2c3e50, #4a6491);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .info-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border-left: 5px solid #667eea;
        }}
        
        .info-card h3 {{
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.2em;
        }}
        
        .info-card p {{
            color: #666;
            line-height: 1.6;
        }}
        
        .results-section {{
            padding: 30px;
        }}
        
        .results-section h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        
        .host-card {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #e0e0e0;
        }}
        
        .host-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .host-ip {{
            font-weight: bold;
            color: #2c3e50;
            font-size: 1.3em;
        }}
        
        .host-status {{
            background: #28a745;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }}
        
        .ports-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        
        .ports-table th {{
            background: #2c3e50;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        
        .ports-table td {{
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .port-open {{
            color: #dc3545;
            font-weight: bold;
        }}
        
        .port-closed {{
            color: #6c757d;
        }}
        
        .footer {{
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 30px;
        }}
        
        .timestamp {{
            color: #95a5a6;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 10px;
        }}
        
        .badge-discovery {{ background: #17a2b8; color: white; }}
        .badge-quick {{ background: #28a745; color: white; }}
        .badge-full {{ background: #dc3545; color: white; }}
        .badge-udp {{ background: #6f42c1; color: white; }}
        
        .scan-type {{
            font-size: 1.1em;
            margin-top: 10px;
        }}
        
        @media (max-width: 768px) {{
            .info-grid {{
                grid-template-columns: 1fr;
            }}
            
            .host-header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }}
        }}
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Network Security Scan Report</h1>
            <p class="scan-type">
                <span class="badge badge-{scan_type}">{scan_type.upper()}</span>
                Scan Report
            </p>
        </div>
        
        <div class="info-grid">
            <div class="info-card">
                <h3><i class="fas fa-bullseye"></i> Target</h3>
                <p>{target}</p>
            </div>
            
            <div class="info-card">
                <h3><i class="fas fa-calendar-alt"></i> Scan Date</h3>
                <p>{timestamp}</p>
            </div>
            
            <div class="info-card">
                <h3><i class="fas fa-tasks"></i> Scan Type</h3>
                <p>{scan_type.capitalize()} Scan</p>
            </div>
            
            <div class="info-card">
                <h3><i class="fas fa-file-alt"></i> Report Generated</h3>
                <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
        
        <div class="results-section">
            <h2><i class="fas fa-server"></i> Scan Results</h2>
            
            <!-- Aquí podrías agregar parsing específico de los resultados -->
            <div class="host-card">
                <div class="host-header">
                    <div class="host-ip">
                        <i class="fas fa-desktop"></i> Scan Complete
                    </div>
                    <div class="host-status">SUCCESS</div>
                </div>
                
                <p>Detailed scan results are available in the raw output files.</p>
                <p class="timestamp">
                    <i class="fas fa-info-circle"></i> 
                    For detailed port information, check the corresponding .txt file
                </p>
            </div>
            
            <h2 style="margin-top: 30px;"><i class="fas fa-chart-bar"></i> Statistics</h2>
            <table class="ports-table">
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                    <th>Description</th>
                </tr>
                <tr>
                    <td><i class="fas fa-network-wired"></i> Target Network</td>
                    <td>{target}</td>
                    <td>Scanned IP/Range</td>
                </tr>
                <tr>
                    <td><i class="fas fa-scan"></i> Scan Profile</td>
                    <td>{scan_type}</td>
                    <td>Type of scan performed</td>
                </tr>
                <tr>
                    <td><i class="fas fa-clock"></i> Scan Duration</td>
                    <td>N/A</td>
                    <td>Time taken for scan</td>
                </tr>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated with <i class="fas fa-heart" style="color: #e74c3c;"></i> by Advanced Network Scanner</p>
            <p class="timestamp">Security Tool v1.0 • Report ID: {datetime.now().strftime('%Y%m%d%H%M%S')}</p>
        </div>
    </div>
    
    <script>
        // Script para interactividad básica
        document.addEventListener('DOMContentLoaded', function() {{
            console.log('Network Scan Report loaded successfully');
            
            // Agregar fecha actual si no hay timestamp
            const timestampElements = document.querySelectorAll('.timestamp');
            timestampElements.forEach(el => {{
                if (el.textContent.includes('N/A')) {{
                    el.textContent = new Date().toLocaleString();
                }}
            }});
        }});
    </script>
</body>
</html>
"""
        
        # Guardar HTML
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        print(f"✅ Reporte HTML generado: {html_file}")
        print(f"   Ábrelo en tu navegador: firefox {html_file} &")
        
        return html_file
        
    except Exception as e:
        print(f"❌ Error convirtiendo JSON a HTML: {e}")
        return None

def main():
    """Función principal"""
    print("🔄 JSON to HTML Converter")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        # Buscar archivos JSON automáticamente
        json_files = list(Path("scan_results").glob("*.json"))
        
        if not json_files:
            print("📁 No se encontraron archivos JSON en scan_results/")
            print("\nUso: python3 json_to_html.py <archivo.json>")
            print("   O ejecuta sin argumentos para procesar todos")
            return
        
        print(f"📂 Encontrados {len(json_files)} archivos JSON:")
        for i, json_file in enumerate(json_files[:5], 1):
            print(f"  {i}. {json_file.name}")
        
        if len(json_files) > 5:
            print(f"  ... y {len(json_files) - 5} más")
        
        print("\n📊 Procesando todos los archivos...")
        for json_file in json_files:
            json_to_html(str(json_file))
        
        print(f"\n✅ Todos los reportes generados en scan_results/")
        
    else:
        # Procesar archivo específico
        json_file = sys.argv[1]
        if not os.path.exists(json_file):
            print(f"❌ Archivo no encontrado: {json_file}")
            return
        
        json_to_html(json_file)

if __name__ == "__main__":
    main()
