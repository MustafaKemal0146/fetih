import sys
import json
import os
import subprocess
from datetime import datetime

# Path management
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR, "Core"))

try:
    from SETH_Locale import get_text
except ImportError:
    # Fallback if manual run from elsewhere
    def get_text(k, **kwargs): return f"[{k}]"

# Etkileşimli ortam değişkenlerini devre dışı bırak
os.environ["SETH_WEB"] = "1"
os.environ["TERM"] = "dumb"

def create_latex_report(target, scan_type, raw_data):
    # LaTeX Rapor dizini (Mühürlü Arşiv)
    reports_dir = os.path.join(BASE_DIR, "Reports", "SETH_Archives")
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    latex_file = os.path.join(reports_dir, f"seth_rapor_{scan_type}_{target.replace('.', '_')}_{timestamp}.tex")
    
    latex_content = f"""\\documentclass[12pt,a4paper]{{article}}
\\usepackage[utf8]{{inputenc}}
\\usepackage[T1]{{fontenc}}
\\usepackage[turkish]{{babel}}
\\usepackage{{geometry}}
\\geometry{{a4paper, margin=2cm}}
\\usepackage{{color}}
\\usepackage{{graphicx}}
\\usepackage{{listings}}
\\usepackage{{hyperref}}

\\title{{\\textbf{{SETH - Otonom Siber Operasyon Raporu}}}}
\\author{{SETH Otonom Ajanı}}
\\date{{\\today}}

\\begin{{document}}
\\maketitle

\\section*{{Operasyon Özeti}}
\\textbf{{Hedef:}} {target}\\\\
\\textbf{{Tarih:}} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\\\
\\textbf{{Saldırı Vektörü:}} {scan_type}

\\section*{{Zafiyet ve İstismar Dökümü}}
Aşağıdaki veriler otonom operasyon modülü tarafından tespit edilmiş ve/veya istismar edilmiştir.
\\begin{{lstlisting}}[language=bash, breaklines=true, basicstyle=\\small\\ttfamily]
"""
    for line in raw_data:
        latex_content += line + "\n"
        
    seal = get_text("NO_SYSTEM_SAFE")
    latex_content += f"""\\end{{lstlisting}}

\\vspace{{2cm}}
\\hrule
\\vspace{{0.5cm}}
\\noindent \\textit{{{seal}}}

\\end{{document}}
"""
    with open(latex_file, "w", encoding="utf-8") as f:
        f.write(latex_content)
        
    return latex_file

def run_action(target, action):
    reports_dir = os.path.join(BASE_DIR, "Reports", "SETH_Archives")
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    try:
        raw_output = []
        output_file = ""
        
        print(get_text("SCAN_STARTING", target=target))
        
        if action == "nmap":
            output_file = os.path.join(reports_dir, "nmap_scan.txt")
            proc = subprocess.run(["nmap", "-sV", "-T4", "--top-ports", "100", target, "-oN", output_file], capture_output=True, text=True, timeout=300)
            if proc.returncode != 0: return {"status": "error", "message": proc.stderr}
            raw_output = proc.stdout.split('\n')[:30]
            
        elif action == "nuclei":
            output_file = os.path.join(reports_dir, "nuclei_scan.txt")
            proc = subprocess.run(["nuclei", "-u", target, "-silent", "-o", output_file], capture_output=True, text=True, timeout=300)
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    raw_output = f.read().splitlines()
            else:
                raw_output = ["Nuclei zafiyet bulamadı."]
                
        elif action == "sqlmap":
            output_file = os.path.join(reports_dir, "sqlmap_scan.txt")
            proc = subprocess.run(["sqlmap", "-u", target, "--batch", "--random-agent"], capture_output=True, text=True, timeout=300)
            raw_output = proc.stdout.split('\n')[:50]
            with open(output_file, "w") as f:
                f.write("\n".join(raw_output))
                
        else:
            return {"status": "error", "message": "Bilinmeyen eylem (Action)."}
            
        # LaTeX Raporu Oluştur
        latex_file = create_latex_report(target, action.upper(), raw_output)
        
        # HTML/TXT Mührü
        seal = get_text("NO_SYSTEM_SAFE")
        if os.path.exists(output_file):
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(f"\n{seal}\n")
                
        print(get_text("REPORT_GENERATED", file=latex_file))
        
        return {
            "status": "success",
            "target": target,
            "scan_type": action.upper(),
            "output_file": output_file,
            "latex_report": latex_file,
            "raw_summary": raw_output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps({"status": "error", "message": "Hedef veya eylem eksik."}))
        sys.exit(1)
    
    target = sys.argv[1]
    action = sys.argv[2]
    result = run_action(target, action)
    print(json.dumps(result))
